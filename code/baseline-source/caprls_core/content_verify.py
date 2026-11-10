"""Content-boundary verification harness."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from caprls_core.content_falsifier import (
    falsify_head_replan,
    lift_named_cte,
    sha256_canonical_json,
    sha256_plain,
    split_access_root,
)
from caprls_core.content_psql import ContentPostgresEnv, quote_literal, run_script
from caprls_core.content_spec_audit import require_audit

RECEIPT_SCHEMA = "caprls-content-receipt-v1"
SUMMARY_SCHEMA = "caprls-content-summary-v1"
HARNESS_MODULES = (
    "content_verify.py",
    "content_reference.py",
    "content_psql.py",
    "content_spec_audit.py",
)
SOURCE_GLOBS = (
    "caprls_core/**/*.py",
    "planner/**/*.py",
    "sql/**/*.sql",
    "manifests/**/*.yaml",
    "specs/content_cells.yaml",
    "specs/selection_difference_classification.yaml",
)
ACTUAL_TABLE = "caprls_content_actual"
REFERENCE_TABLE = "caprls_content_reference"
WITNESS_CAP = 20
CROSSVALIDATION_ROW_THRESHOLD = 20000
MARKER = "@@CAPRLS:"

#: §7.3 — 16 pinned GUCs.  ``to_jsonb(row)::text`` and any byte-level digest
#: depend on far more than the 6 the existing E3 transaction script sets.
PINNED_GUCS: Tuple[Tuple[str, str], ...] = (
    ("search_path", "pg_catalog, public"),
    ("jit", "off"),
    ("max_parallel_workers_per_gather", "0"),
    ("plan_cache_mode", "force_custom_plan"),
    ("row_security", "on"),
    ("DateStyle", "ISO, YMD"),
    ("IntervalStyle", "iso_8601"),
    ("TimeZone", "UTC"),
    ("extra_float_digits", "0"),
    ("lc_numeric", "C"),
    ("lc_monetary", "C"),
    ("lc_time", "C"),
    ("bytea_output", "hex"),
    ("client_encoding", "UTF8"),
    ("standard_conforming_strings", "on"),
    ("client_min_messages", "warning"),
)
assert len(PINNED_GUCS) == 16

#: F1 — list-valued GUCs must be emitted in **identifier** form.
#: ``SET LOCAL search_path = 'pg_catalog, public'`` installs *one* schema
#: literally named ``pg_catalog, public``, taking ``public`` off the path in
#: every comparison transaction.  Seventeen of the 52 cells read
#: ``share_acl`` / ``group_membership`` / ``purpose_policy`` unqualified — and
#: so does the frozen *candidate* SQL, so qualifying the reference would leave
#: the candidate broken and introduce an asymmetry against frozen text.  Only
#: repairing the GUC fixes both sides.  The other 15 keep ``quote_literal``.
IDENTIFIER_FORM_GUCS = frozenset({"search_path"})


def render_pinned_guc(name: str, value: str) -> str:
    if name in IDENTIFIER_FORM_GUCS:
        if re.fullmatch(r"[a-z_][a-z0-9_]*(\s*,\s*[a-z_][a-z0-9_]*)*", value) is None:
            raise ContentVerifyError(
                "identifier-form GUC {} has an unsafe value: {!r}".format(name, value)
            )
        return "SET LOCAL {} TO {};".format(name, value)
    return "SET LOCAL {} = {};".format(name, quote_literal(value))

#: Modes excluded from every denominator, with reason codes (§8.6).
EXCLUDED_MODE_PATTERNS = (
    ("contract_reject:*", "not an applicable policy-enforcement mode"),
    ("artifact_unavailable:*", "artifact precondition unmet"),
    ("metadata_invalid:*", "artifact metadata invalid"),
    ("ordinary-no-contract", "no contract applied"),
    ("guard-late-only", "ablation"),
    ("unsafe-pushdown-positive-control", "diagnostic positive control"),
    ("no-*", "ablation"),
    ("template-oracle", "oracle enumeration, not a selection"),
)

NATIVE_RLS_TEMPLATES = frozenset(
    {"native_pg_rls_v1", "native_pg_rls_physical_design_v1"}
)


class ContentVerifyError(RuntimeError):
    """Fail-closed harness error."""


class ContentRefusal(ContentVerifyError):
    """A condition that refuses the package rather than failing a cell (§10.1).

    F8 (v2.3 clause D): a refusal **carries the partially-built receipt**.  The
    previous implementation caught the refusal and rebuilt a bare skeleton,
    discarding the ``candidate`` block ``verify_cell`` had already populated —
    which, for a selection-difference refusal, is precisely the attribution
    evidence: the observed template, its plan id, its runner digest, its
    prospective cost and the per-candidate cost vector.  Recovering that after
    the fact cost 48 re-derivations of a planner path whose output is not
    reproducible, so the run's actual values were lost for good.
    """

    def __init__(self, message: str, partial: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.partial = dict(partial) if partial else None


# ===========================================================================
# A. Identity (§7)
# ===========================================================================
def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def declared_source_files(root: Path) -> List[str]:
    """The declared, sorted source file list.  The declaration is itself digested."""

    root = Path(root)
    seen: List[str] = []
    for pattern in SOURCE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            rel = str(path.relative_to(root))
            if rel not in seen:
                seen.append(rel)
    return sorted(seen)


def source_identity(root: Path) -> Dict[str, Any]:
    files = declared_source_files(root)
    listing = "\n".join(files) + "\n"
    digest = hashlib.sha256()
    for rel in files:
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(Path(root) / rel).encode("utf-8"))
        digest.update(b"\0")
    return {
        "source_digest": "sha256:" + digest.hexdigest(),
        "source_file_list_digest": sha256_plain(listing),
        "source_file_count": len(files),
        "source_file_list": files,
        "source_globs": list(SOURCE_GLOBS),
    }


def harness_identity(root: Path) -> Dict[str, Any]:
    here = Path(__file__).parent
    parts = []
    digest = hashlib.sha256()
    for name in HARNESS_MODULES:
        path = here / name
        file_digest = _sha256_file(path)
        parts.append({"module": name, "digest": file_digest})
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("utf-8"))
        digest.update(b"\0")
    return {"harness_digest": "sha256:" + digest.hexdigest(), "harness_modules": parts}


def git_identity(root: Path) -> Dict[str, Any]:
    def _git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(root)] + list(args), text=True, capture_output=True
        )
        if proc.returncode != 0:
            raise ContentVerifyError("git failed: " + " ".join(args))
        return proc.stdout

    head = _git("rev-parse", "HEAD").strip()
    porcelain = _git("status", "--porcelain")
    return {
        "head": head,
        "working_tree_clean": porcelain.strip() == "",
        "status_digest": sha256_plain(porcelain),
    }


def merkle_root(entries: Sequence[Tuple[str, str]]) -> str:
    """Leaves sorted by path; ``leaf = sha256(0x00 || path || 0x00 || filehash)``;
    ``internal = sha256(0x01 || left || right)``; last node duplicated on odd levels."""

    if not entries:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    level = []
    for path, file_hash in sorted(entries):
        payload = b"\x00" + path.encode("utf-8") + b"\x00" + file_hash.encode("utf-8")
        level.append(hashlib.sha256(payload).digest())
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return "sha256:" + level[0].hex()


def four_layer_declaration(
    identity: Mapping[str, Any],
    selection_same: Optional[int] = None,
    runner_byte_identical: Optional[int] = None,
) -> Dict[str, Any]:
    """§7.5 — the four-layer identity declaration, verbatim template.

    The **Source** clause's closure statement is conditional on ``n`` (closing
    identity_audit V2-N6): differences are closed only for the cells reported
    ``runner_identity: byte_identical``; for the rest the difference is
    disclosed with its ``selection_difference_cause`` and is *not* closed.  No
    difference is closed by inspection.
    """

    git = identity["git"]
    tree = "clean" if git["working_tree_clean"] else "modified: see status_digest"
    n = "<n>" if runner_byte_identical is None else str(runner_byte_identical)
    remaining = "<52-n>" if runner_byte_identical is None else str(52 - runner_byte_identical)
    same = "<n>" if selection_same is None else str(selection_same)
    return {
        "source": (
            "This package was produced under a single source snapshot, commit {head}, "
            "source digest {sd}, file-list digest {fl}, working tree {tree}. The frozen "
            "campaigns it refers to were produced under different snapshots: E2 and E10 "
            "under d8b6404, the ordinary E3 campaign under 441c31f, and the existing E3 "
            "canonical-content layer under 660a636. planner/root_selection.py, "
            "planner/verifier/static.py, caprls_core/e3_main.py and caprls_core/e10_study.py "
            "differ from at least one of those commits. For the {n} cells reported "
            "runner_identity: byte_identical, the difference is closed by the byte-level "
            "recomposition check; for the remaining {rem} cells the difference is disclosed "
            "with its selection_difference_cause and is NOT closed. No difference is closed "
            "by inspection.".format(
                head=git["head"], sd=identity["source"]["source_digest"],
                fl=identity["source"]["source_file_list_digest"], tree=tree,
                n=n, rem=remaining,
            )
        ),
        # Clause B — three data states, three fingerprints, three databases.
        # The unconditional "seeds 42 and 52" sentence is deleted: no single
        # database can hold both, and the package must never claim one state.
        "data": (
            "The datasets were rebuilt for this package as THREE distinct data states, each "
            "in its own database on one cluster, each built before the package started by "
            "that family's own frozen builder, and each fingerprinted separately at that "
            "family's session start: {states}. "
            "synthetic_saas is regenerated by caprls_core/synthetic_saas.py, which is "
            "byte-identical to the frozen campaigns' commit and contains no pseudo-random "
            "component; its regeneration is content-identical by construction, and a content "
            "digest is recorded here for the first time. No recorded fingerprint of the "
            "frozen campaigns' data exists for seed 52 against which to compare, and the one "
            "seed-42 fingerprint that exists was written at a different commit (7ee11f14b) "
            "across which the generator changed. The TPC-H SF1 and JOB tables are COPY-loaded "
            "from local source files that carry no recorded content digest in any frozen "
            "artefact; their per-file digests ({copies} files) are likewise first recorded "
            "here. No claim of byte-identity with the frozen campaigns' data is made or is "
            "verifiable.".format(
                states="; ".join(
                    "{fam} = {ds} {scale}{seed} in database {db} "
                    "(fingerprint {fp})".format(
                        fam=fam,
                        ds=block.get("dataset"),
                        scale=block.get("scale"),
                        seed=(
                            " seed {}".format(block["seed"])
                            if block.get("seed") is not None
                            else " (seed decorative)"
                        ),
                        db=block.get("database"),
                        fp=block.get("fingerprint_digest"),
                    )
                    for fam, block in sorted(
                        identity.get("dataset_fingerprint_by_family", {}).items()
                    )
                )
                or "none recorded",
                copies=(
                    identity.get("dataset_fingerprint_by_family", {})
                    .get("E3", {})
                    .get("copy_input_count", 0)
                ),
            )
        ),
        "plan": (
            "Selection was re-run under {head}. selection_identity: same in {same}/52 cells; "
            "runner_identity: byte_identical in {n}/52. The compared object is the "
            "enforcement boundary, not the timed statement: verbatim_subplan_planner_anchored "
            "in 33 cells (E3), verbatim_subplan_text_anchored in 5 (E10 Q4/Q5/Q6/Q8/Q10), and "
            "re_rendered_projection in 14 (E2 x8; E10 Q1/Q2/Q3/Q7/Q9/Q11). Of the 52 "
            "boundaries, 51 are exact_authorized and one (E10 Q5) is "
            "guard_candidate_not_exact.".format(head=git["head"], same=same, n=n)
        ),
        "harness": (
            "New: content_verify.py, content_reference.py, content_psql.py (private "
            "duplicated psql executor; postgres_runner.py untouched), content_spec_audit.py, "
            "digest {hd}; the reference generator runs in an isolated interpreter whose "
            "resident-module list is recorded per cell.".format(
                hd=identity["harness"]["harness_digest"]
            )
        ),
        "therefore": (
            "This package verifies content-level correctness OF THE PLANS SELECTED UNDER "
            "SNAPSHOT {head}. It does not retroactively certify the plans measured in the "
            "frozen performance runs, and no latency claim is derived from it.".format(
                head=git["head"]
            )
        ),
    }


#: Clause D — files excluded from the set the Merkle root covers.  The root must
#: live outside the set it covers, or writing it changes the set and the
#: archived root becomes irreproducible from its own directory.
INTEGRITY_EXCLUDED = frozenset({"MANIFEST.sha256", "INTEGRITY.json"})


def write_manifest_and_merkle(run_dir: Path) -> Dict[str, Any]:
    """``MANIFEST.sha256`` for every file in the run directory except the
    integrity artefacts themselves (Clause D)."""

    run_dir = Path(run_dir)
    manifest_path = run_dir / "MANIFEST.sha256"
    entries: List[Tuple[str, str]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(run_dir))
        if rel in INTEGRITY_EXCLUDED:
            continue
        entries.append((rel, _sha256_file(path)))
    with manifest_path.open("w", encoding="utf-8") as handle:
        for rel, file_hash in entries:
            handle.write("{}  {}\n".format(file_hash.split(":", 1)[1], rel))
    return {
        "manifest_path": manifest_path.name,
        "package_merkle_root": merkle_root(entries),
        "file_count": len(entries),
        "excluded_from_covered_set": sorted(INTEGRITY_EXCLUDED),
        "reproduce": (
            "merkle_root([(path, 'sha256:' + hash) for hash, path in MANIFEST.sha256]) "
            "with leaves sorted by path"
        ),
    }


# ---------------------------------------------------------------------------
# A2. Data identity (§7.2) and statistics identity (§6.4)
# ---------------------------------------------------------------------------
#: §7.2 — mandatory content digests for every protected and policy-input relation.
CONTENT_DIGEST_RELATIONS = (
    "document", "ticket", "invoice", "share_acl", "group_membership",
    "purpose_policy", "user_account", "synthetic_context",
    "tpch_customer", "job_title",
)
#: §7.2 — count-level only, **declared as such**, for continuation-only relations.
COUNT_ONLY_RELATIONS = (
    "tpch_lineitem", "tpch_orders", "job_cast_info", "job_movie_companies",
)
#: §7.2 — the E3 tables are ``COPY``-loaded and have no generator, so the seed is
#: decorative.  The only anchor is a per-file digest for every COPY input, which
#: no frozen artefact records; these are first recorded here.
COPY_INPUT_GLOBS = ("datasets/tpch/**/*", "datasets/imdb/csv/*.csv")


def _content_digest_sql(relation: str) -> str:
    """§7.2, deterministic form (closing identity_audit V2-N3).

    Inside an *aggregate's* ``ORDER BY``, an integer literal is an ordinary
    constant expression, not a positional reference, so ``ORDER BY 1`` would
    leave the aggregation order to the scan.  This sorts on the value itself.
    """

    return (
        "SELECT 'sha256:' || encode(sha256(convert_to(COALESCE(string_agg("
        "encode(sha256(convert_to(to_jsonb(t)::text, 'UTF8')), 'hex'), '' "
        "ORDER BY encode(sha256(convert_to(to_jsonb(t)::text, 'UTF8')), 'hex') "
        "COLLATE \"C\"), ''), 'UTF8')), 'hex') FROM public.{} t".format(relation)
    )


#: Clause B — each family's declared data state, and the relations that state
#: actually contains.  A family's fingerprint never reaches into another
#: family's database, because there is no longer one to reach into.
FAMILY_DATA_STATE = {
    "E2": {
        "dataset": "synthetic_saas", "scale": "1e5", "seed": 42,
        "builder": "caprls_core.synthetic_saas.generate_synthetic_saas "
                   "(sql/schema/010_synthetic_saas.sql, via cli generate-data)",
        "content_relations": ("document", "ticket", "invoice", "share_acl",
                              "group_membership", "purpose_policy", "user_account",
                              "synthetic_context"),
        "count_only_relations": (),
        "statistics_relations": ("document", "ticket", "invoice"),
        "has_copy_inputs": False,
    },
    "E10": {
        "dataset": "synthetic_saas", "scale": "1e5", "seed": 52,
        "builder": "caprls_core.synthetic_saas.generate_synthetic_saas "
                   "(sql/schema/010_synthetic_saas.sql, via cli generate-data)",
        "content_relations": ("document", "ticket", "invoice", "share_acl",
                              "group_membership", "purpose_policy", "user_account",
                              "synthetic_context"),
        "count_only_relations": (),
        "statistics_relations": ("document", "ticket", "invoice"),
        "has_copy_inputs": False,
    },
    "E3": {
        "dataset": "tpch_sf1_plus_job_full", "scale": "SF1/full", "seed": None,
        "builder": "caprls_core.e3_main._prepare_database",
        "content_relations": ("tpch_customer", "job_title", "share_acl",
                              "group_membership"),
        "count_only_relations": ("tpch_orders", "tpch_lineitem",
                                 "job_movie_companies", "job_cast_info"),
        "statistics_relations": ("tpch_customer", "job_title"),
        "has_copy_inputs": True,
    },
}


def _e3_copy_inputs(root: Path, tpch_scale: str, job_scale: str) -> Dict[str, str]:
    """Per-file digest for **every COPY input**, from the frozen accessors.

    §7.2's anchor for E3 is "a per-file ``source_file_digest`` for every ``COPY``
    input".  The frozen accessors name exactly the files the loader ``COPY``s,
    which is both literally correct and avoids sweeping unrelated scale
    directories and the volume's AppleDouble ``._`` sidecars.
    """

    from caprls_core import e3_main as e3

    paths: List[Path] = []
    try:
        if tpch_scale in getattr(e3, "REAL_TPCH_SCALES", ()):
            paths.extend(Path(p) for p in e3._tpch_real_data_files(root, tpch_scale))
        if job_scale in getattr(e3, "REAL_JOB_SCALES", ()):
            paths.extend(Path(p) for p in e3._job_real_data_files(root))
    except Exception:  # noqa: BLE001 - fall back to the declared globs
        paths = []
    if not paths:
        for pattern in COPY_INPUT_GLOBS:
            paths.extend(
                p for p in sorted(Path(root).glob(pattern))
                if p.is_file() and not p.name.startswith("._")
            )
    digests: Dict[str, str] = {}
    for path in sorted(set(paths)):
        if not Path(path).is_file():
            continue
        try:
            key = str(Path(path).relative_to(root))
        except ValueError:
            key = str(path)
        digests[key] = _sha256_file(Path(path))
    return digests


def dataset_fingerprint(
    root: Path,
    pg_env: ContentPostgresEnv,
    family: str,
    *,
    tpch_scale: str = "",
    job_scale: str = "",
) -> Dict[str, Any]:
    """Fingerprint **one family's** data state, in that family's own database.

    §7.2 declares three distinct data states and says the package must never
    claim one; Clause B is that sentence's landing.  ``synthetic_saas`` is
    content-identical by construction (the generator has no RNG at all and is
    byte-identical to the frozen campaigns' commit), but **no claim of
    byte-identity with the frozen campaigns' data is made or is verifiable**:
    the only seed-42 fingerprint on disk was written at a different commit
    across which the generator changed, and no seed-52 fingerprint exists
    anywhere.
    """

    from caprls_core.content_psql import run_scalar

    state = FAMILY_DATA_STATE[family]
    content: Dict[str, str] = {}
    for relation in state["content_relations"]:
        content[relation] = run_scalar(_content_digest_sql(relation), pg_env)
    counts: Dict[str, int] = {}
    for relation in state["count_only_relations"]:
        counts[relation] = int(
            run_scalar("SELECT count(*) FROM public.{}".format(relation), pg_env)
        )
    fingerprint: Dict[str, Any] = {
        "family": family,
        "database": pg_env.database,
        "dataset": state["dataset"],
        "scale": state["scale"],
        "seed": state["seed"],
        "builder": state["builder"],
        "content_digests": content,
        "count_level_only": counts,
        "count_level_only_declared_as_such": True,
        "byte_identity_with_frozen_campaign_data": "not_claimed_and_not_verifiable",
    }
    if state["seed"] is not None:
        fingerprint["generator_source_digest"] = _sha256_file(
            Path(root) / "caprls_core" / "synthetic_saas.py"
        )
    else:
        fingerprint["seed_is_decorative"] = True
    if state["has_copy_inputs"]:
        copy_inputs = _e3_copy_inputs(root, tpch_scale, job_scale)
        fingerprint["copy_input_digests"] = copy_inputs
        fingerprint["copy_input_count"] = len(copy_inputs)
        fingerprint["copy_input_source"] = (
            "e3_main._tpch_real_data_files + _job_real_data_files (frozen accessors)"
        )
    fingerprint["fingerprint_digest"] = sha256_plain(
        json.dumps(fingerprint, sort_keys=True, separators=(",", ":"))
    )
    return fingerprint


def statistics_digest(pg_env: ContentPostgresEnv, family: str) -> Dict[str, str]:
    """§6.4 — per protected relation, in that family's own database.

    The named likely cause of a selection difference is ``ANALYZE`` sampling:
    selection consumes EXPLAIN costs, which depend on statistics, which are
    sampled for large relations and are therefore not deterministic across
    cluster rebuilds even with byte-identical code and data.
    """

    from caprls_core.content_psql import run_scalar

    digests: Dict[str, str] = {}
    for relation in FAMILY_DATA_STATE[family]["statistics_relations"]:
        digests[relation] = run_scalar(
            "SELECT 'sha256:' || encode(sha256(convert_to(COALESCE(string_agg("
            "attname || ':' || COALESCE(null_frac::text, '') || ':' "
            "|| COALESCE(n_distinct::text, '') || ':' "
            "|| COALESCE(avg_width::text, ''), '|' ORDER BY attname), ''), 'UTF8')), "
            "'hex') FROM pg_stats WHERE schemaname = 'public' AND tablename = {}".format(
                quote_literal(relation)
            ),
            pg_env,
        )
    return digests


# ---------------------------------------------------------------------------
# A3. Per-family database provisioning (Clause A)
# ---------------------------------------------------------------------------
def default_database_for(base: str, family: str) -> str:
    return "{}_{}".format(base, family.lower())


def provision_family(
    root: Path,
    family: str,
    pg_env: ContentPostgresEnv,
    *,
    manifest_path: Optional[Path] = None,
    create_database: bool = True,
) -> Dict[str, Any]:
    """Build ONE family's database with THAT family's own frozen builder.

    Never hand-written DDL, and never against another family's database.  The
    two fixture families require **mutually unsatisfiable schemas on the same
    two relation names** — ``group_membership.user_id`` is ``bigint`` in
    ``sql/schema/010_synthetic_saas.sql`` and ``text`` in ``e3_main``;
    ``share_acl.relname`` is ``'document'`` there and ``'public.tpch_customer'``
    here — so no ordering, no ``CASCADE`` and no repair sequence reconciles
    them.  Physical separation is the only fix that touches neither predicate.

    ``010_synthetic_saas.sql`` also uses ``CREATE TABLE IF NOT EXISTS``, so
    re-running the generator over another family's leftover tables keeps the
    other family's columns and then fails on insert.  The generator is the right
    tool only against a database no other family has touched — which is exactly
    what this function guarantees.
    """

    if family not in FAMILY_DATA_STATE:
        raise ContentVerifyError("unknown family: {}".format(family))
    root = Path(root)
    state = FAMILY_DATA_STATE[family]
    created = False
    if create_database:
        created = _create_database_if_absent(pg_env)

    from caprls_core.postgres_runner import PostgresEnv

    legacy = PostgresEnv(
        host=pg_env.host, port=pg_env.port, user=pg_env.user, database=pg_env.database
    )
    detail: Dict[str, Any] = {}
    if family in ("E2", "E10"):
        from caprls_core.synthetic_saas import generate_synthetic_saas

        result = generate_synthetic_saas(
            root=root, pg_env=legacy, scale=str(state["scale"]),
            seed=int(state["seed"]), verify=True, output_dir=None,
        )
        detail = {
            "dataset_id": result.dataset_id,
            "table_counts": dict(result.table_counts),
            "verification": {k: bool(v) for k, v in result.verification.items()},
        }
        if not all(result.verification.values()):
            raise ContentVerifyError(
                "{}: generate_synthetic_saas verification failed: {}".format(
                    family, result.verification
                )
            )
    else:
        from caprls_core import e3_main as e3

        manifest_path = manifest_path or (
            root / "manifests" / "experiments" / "e3_standard_sf1_rawpg.yaml"
        )
        with Path(manifest_path).open("r", encoding="utf-8") as handle:
            manifest = yaml.safe_load(handle) or {}
        scale_by_dataset = {
            str(item.get("name")): str(item.get("scale", "reduced"))
            for item in manifest.get("datasets", ())
            if isinstance(item, Mapping)
        }
        pg_version = e3._prepare_database(
            root, legacy,
            tpch_scale=scale_by_dataset.get("tpch", ""),
            job_scale=scale_by_dataset.get("job", ""),
        )
        detail = {
            "manifest": str(Path(manifest_path).name),
            "tpch_scale": scale_by_dataset.get("tpch", ""),
            "job_scale": scale_by_dataset.get("job", ""),
            "pg_version": pg_version,
        }
    return {
        "family": family,
        "database": pg_env.database,
        "database_created": created,
        "builder": state["builder"],
        "cross_family_ddl": False,
        "detail": detail,
    }


def _create_database_if_absent(pg_env: ContentPostgresEnv) -> bool:
    """`createdb` the family's database if it does not exist yet."""

    import shutil
    import subprocess as _subprocess

    from caprls_core.content_psql import ContentPsqlError, run_scalar

    admin = ContentPostgresEnv(
        host=pg_env.host, port=pg_env.port, user=pg_env.user, database="postgres"
    )
    exists = run_scalar(
        "SELECT count(*)::text FROM pg_database WHERE datname = {}".format(
            quote_literal(pg_env.database)
        ),
        admin,
    )
    if int(exists) > 0:
        return False
    createdb = shutil.which("createdb")
    if not createdb:
        raise ContentPsqlError("createdb not found on PATH")
    proc = _subprocess.run(
        [createdb, pg_env.database], env=admin.to_env(), text=True, capture_output=True
    )
    if proc.returncode != 0:
        raise ContentPsqlError(
            "createdb {} failed: {}".format(pg_env.database, proc.stderr)
        )
    return True


# ===========================================================================
# B. Spec loading
# ===========================================================================
def load_spec(spec_path: Path) -> Mapping[str, Any]:
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != "caprls-content-cells-v1":
        raise ContentVerifyError("content cell spec has the wrong schema")
    if len(data["cells"]) != 52:
        raise ContentVerifyError("content cell spec must declare exactly 52 cells")
    return data


CLASSIFICATION_SCHEMA = "caprls-selection-difference-classification-v1"


def load_selection_classification(path: Path) -> Mapping[str, Any]:
    """Load the pre-signed classification table (v2.3 clause A).

    Human classification enters **only** through this file, signed and
    digest-recorded before the run.  The harness never self-classifies: it may
    set ``selection_difference_cause`` from an entry **only when the observed
    template is inside that cell's declared admissible set**, and every other
    difference still sets ``unknown`` and still refuses, exactly as §6.4
    requires.
    """

    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != CLASSIFICATION_SCHEMA:
        raise ContentVerifyError("selection classification table has the wrong schema")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ContentVerifyError("selection classification table has no entries")
    for entry in entries:
        for key in (
            "cell_id", "short_id", "frozen_selected_template_id",
            "admissible_observed_templates", "cause", "evidence_ref",
        ):
            if not entry.get(key):
                raise ContentVerifyError(
                    "classification entry {} lacks {}".format(entry.get("short_id"), key)
                )
    return data


def classify_selection_difference(
    classification: Mapping[str, Any],
    cell: Mapping[str, Any],
    observed_template: str,
) -> Dict[str, Any]:
    """Return the cause for an observed selection difference, or ``unknown``."""

    for entry in classification.get("entries", ()):
        if entry["short_id"] != cell["short_id"]:
            continue
        if entry["cell_id"] != cell["cell_id"]:
            raise ContentVerifyError(
                "classification entry {} does not match the spec's cell_id".format(
                    entry["short_id"]
                )
            )
        if entry["frozen_selected_template_id"] != cell["frozen"]["selected_template_id"]:
            raise ContentVerifyError(
                "classification entry {} declares a stale frozen template".format(
                    entry["short_id"]
                )
            )
        admissible = list(entry["admissible_observed_templates"])
        if observed_template in admissible:
            return {
                "selection_difference_cause": entry["cause"],
                "classified_by": "pre_signed_table",
                "admissible_observed_templates": admissible,
                "selection_stability": entry.get("selection_stability"),
                "evidence_ref": entry["evidence_ref"],
            }
        return {
            "selection_difference_cause": "unknown",
            "classified_by": "observed_template_outside_admissible_set",
            "admissible_observed_templates": admissible,
            "selection_stability": entry.get("selection_stability"),
            "evidence_ref": entry["evidence_ref"],
        }
    return {
        "selection_difference_cause": "unknown",
        "classified_by": "cell_not_listed_in_classification_table",
        "admissible_observed_templates": [],
        "selection_stability": None,
        "evidence_ref": None,
    }


def ordered_cells(spec: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """Deterministic execution order: family, then ``cell_id`` (§8.5)."""

    family_rank = {"E2": 0, "E3": 1, "E10": 2}
    return sorted(spec["cells"], key=lambda c: (family_rank[c["family"]], c["cell_id"]))


# ===========================================================================
# C. Candidate side (§6) — Option B: re-run admission + selection,
#    take the selection result only.
# ===========================================================================
@dataclass
class CandidateBoundary:
    selected_template_id: str
    selected_plan_id: Optional[str]
    selected_runner_digest: Optional[str]
    runner_sql: str
    boundary_sql: str
    prospective_total_cost: Optional[float]
    predicate_text: Optional[str]
    extraction_proof: Dict[str, Any] = field(default_factory=dict)
    rewrite_diff: Optional[Dict[str, Any]] = None
    #: v2.3 clause B / condition 3 — the full per-candidate prospective cost
    #: vector, on EVERY receipt and not only on refusals.  It is the only
    #: artefact that makes a selection divergence auditable, and the planner
    #: computes it anyway.  Recording it turns "the auditor found this by 48
    #: re-derivations of a non-reproducible path" into a package property.
    candidate_cost_vector: List[Dict[str, Any]] = field(default_factory=list)
    cost_vector_source: Optional[str] = None


class _E3CostVectorCapture:
    """Observe the per-candidate prospective costs the E3 planner already computes.

    ``e3_main`` records ``costs[plan_id] = plan_root["Total Cost"]`` and then
    calls ``_verify_e3_static(template_id, runner_body, explain_json)`` with the
    same EXPLAIN document — but neither the cost map nor the batch that holds it
    is reachable from ``_prepare_cell_live``'s return value, and ``e3_main`` is a
    frozen measurement file that must not be edited.

    So the costs are read *in passing*: for the duration of one
    ``_prepare_cell_live`` call this installs a **pass-through** wrapper around
    ``e3_main._verify_e3_static`` that records ``(template_id, Total Cost)`` and
    then delegates unchanged, restoring the original in ``finally``.  The
    recording is exception-proof: any failure to observe is swallowed, so the
    wrapper can never alter the planner's behaviour or its result.  This is the
    same read-only hook the Cell-10 attribution used.  ``e3_main.py`` stays
    byte-identical.
    """

    def __init__(self, e3: Any) -> None:
        self._e3 = e3
        self._original: Any = None
        self.observations: List[Dict[str, Any]] = []

    def __enter__(self) -> "_E3CostVectorCapture":
        self._original = getattr(self._e3, "_verify_e3_static")
        original = self._original
        observations = self.observations

        def _wrapper(template_id, runner_body, explain_json, *args, **kwargs):
            try:
                cost = explain_json[0]["Plan"]["Total Cost"]
                observations.append(
                    {
                        "template_id": str(template_id),
                        "prospective_total_cost": float(cost),
                        "runner_sql_digest": sha256_plain(str(runner_body)),
                    }
                )
            except Exception:  # noqa: BLE001 - observation must never perturb planning
                pass
            return original(template_id, runner_body, explain_json, *args, **kwargs)

        setattr(self._e3, "_verify_e3_static", _wrapper)
        return self

    def __exit__(self, *exc_info: Any) -> None:
        setattr(self._e3, "_verify_e3_static", self._original)

    def vector(self) -> List[Dict[str, Any]]:
        """Deduplicate by template, keeping the last observation per template."""

        latest: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        for item in self.observations:
            latest[item["template_id"]] = item
        return sorted(latest.values(), key=lambda i: i["template_id"])


def _tokenize_sql(sql: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\S", sql)


def _select_list_span(statement: str) -> Tuple[int, int]:
    """Return the ``[start, end)`` character span of a top-level select list."""

    lowered = statement.lower()
    start = lowered.index("select") + len("select")
    depth = 0
    index = start
    while index < len(statement):
        char = statement[index]
        if char == "'":
            index += 1
            while index < len(statement):
                if statement[index] == "'":
                    if index + 1 < len(statement) and statement[index + 1] == "'":
                        index += 2
                        continue
                    break
                index += 1
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and lowered.startswith("from", index):
            before = statement[index - 1] if index else " "
            after = statement[index + 4] if index + 4 < len(statement) else " "
            if not before.isalnum() and not (after.isalnum() or after == "_"):
                return start, index
        index += 1
    raise ContentVerifyError("could not locate a top-level FROM in the statement")


def rewrite_select_list(statement: str, projection: str) -> Tuple[str, Dict[str, Any]]:
    """Replace the select list, leaving ``FROM``/``WHERE`` byte-identical (§6.2)."""

    start, end = _select_list_span(statement)
    rewritten = statement[:start] + " " + projection + "\n" + statement[end:]
    before_tokens = _tokenize_sql(statement)
    after_tokens = _tokenize_sql(rewritten)
    tail_original = _tokenize_sql(statement[end:])
    tail_rewritten = _tokenize_sql(rewritten[len(statement[:start] + " " + projection + "\n"):])
    diff = {
        "touches": ["select_list"],
        "tail_identical": tail_original == tail_rewritten,
        "original_token_count": len(before_tokens),
        "rewritten_token_count": len(after_tokens),
        "original_select_list": statement[start:end].strip(),
        "rewritten_select_list": projection,
    }
    if not diff["tail_identical"]:
        raise ContentRefusal(
            "re-render touched more than the select list: FROM/WHERE tail differs",
            partial={"refusal_operands": {
                "original_tail_tokens": tail_original[:60],
                "rewritten_tail_tokens": tail_rewritten[:60],
                "original_select_list": diff["original_select_list"],
                "rewritten_select_list": projection,
            }},
        )
    return rewritten.strip(), diff


def strip_ordered_limit_continuation(
    statement: str, source_relation: str, projection: str
) -> Tuple[str, Dict[str, Any]]:
    """E10 Q7 only: the boundary is the MAV scan below the derived table's LIMIT.

    §3.3 declares this a deliberate, disclosed re-render: the executed statement
    projects only ``rid``, and widening to ``(rid, tenant_id)`` buys the package
    its only value-level discrimination (§11.3).  ``ORDER BY``/``LIMIT`` sit
    above the boundary and are excluded (§3.4).
    """

    rewritten = "SELECT {}\nFROM {}".format(projection, source_relation)
    return rewritten, {
        "touches": ["select_list", "continuation_strip"],
        "stripped": ["derived_table", "order_by", "limit"],
        "original_statement": statement.strip(),
        "rewritten_select_list": projection,
        "disclosure": "Q7's executed statement projects only rid; the widening to "
        "(rid, tenant_id) is a declared, disclosed re-render (memo 3.3, 11.3)",
    }


def observed_boundary_relation(sql: str) -> Optional[str]:
    """The relation named by the first top-level ``FROM`` of an extracted boundary.

    Y4.1 operand: the *observed* namespace, to be compared against the declared
    ``boundary.candidate_relation`` before the ``r_c`` containment assertion is
    allowed to mean anything.
    """

    tokens: List[str] = []
    depth = 0
    index = 0
    current: List[str] = []
    while index < len(sql):
        char = sql[index]
        if char == "'":
            index += 1
            while index < len(sql):
                if sql[index] == "'":
                    if index + 1 < len(sql) and sql[index + 1] == "'":
                        index += 2
                        continue
                    break
                index += 1
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if depth == 0 and (char.isalnum() or char in "_."):
            current.append(char)
        else:
            if current:
                tokens.append("".join(current))
                current = []
        index += 1
    if current:
        tokens.append("".join(current))
    reserved = {
        "as", "select", "where", "group", "order", "limit", "on", "join",
        "left", "right", "inner", "outer", "cross", "lateral", "having",
    }
    for position, token in enumerate(tokens):
        if token.lower() != "from" or position + 1 >= len(tokens):
            continue
        following = tokens[position + 1]
        if following.lower() in reserved:
            # A derived table: the FROM item is a parenthesised subquery, whose
            # contents this depth-0 tokenizer deliberately skips.  Report "no
            # single relation" rather than the alias keyword that follows it.
            return None
        return following
    return None


def observed_rid_column(sql: str) -> Optional[str]:
    """The column aliased to the RID carrier in an extracted boundary, if any."""

    match = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)\s+AS\s+__rid\b", sql, re.IGNORECASE)
    if match:
        return match.group(1).split(".")[-1]
    match = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)\s+AS\s+rid\b", sql, re.IGNORECASE)
    if match:
        return match.group(1).split(".")[-1]
    return None


def evaluate_r_c_containment(
    cell: Mapping[str, Any],
    boundary_sql: str,
    selection_identity: Optional[str] = None,
) -> Dict[str, Any]:
    """Content-boundary verification helper."""

    refinement = cell["boundary"]["refinement"]
    declared_relation = cell["boundary"]["candidate_relation"]
    observed_relation = observed_boundary_relation(boundary_sql)
    observed_rid = observed_rid_column(boundary_sql)
    operands = {
        "declared_r_c": refinement.get("r_c"),
        "containment_assert_declared": bool(refinement.get("containment_assert")),
        "declared_candidate_relation": declared_relation,
        "observed_boundary_relation": observed_relation,
        "declared_rid_col": cell["boundary"].get("rid_col"),
        "observed_rid_col": observed_rid,
        "selection_identity_at_extraction": selection_identity,
    }
    if not refinement.get("containment_assert") or not refinement.get("r_c"):
        operands["r_c_containment"] = "not_applicable: no r_c declared for this cell"
        return operands

    # Evaluate the predicate first.  If it holds, it holds — the namespace
    # question never arises, and a check that would have passed is never skipped.
    if refinement["r_c"] in boundary_sql:
        operands["r_c_containment"] = "held"
        return operands

    # It does not hold.  The skip is admissible ONLY when the selection differs
    # *and* the observed boundary reads a different relation than the spec
    # declared — i.e. the declared predicate is namespaced to a relation this
    # plan does not read.  Under a same selection the refusal stands, which is
    # the case refuse #5 exists for.
    same_namespace = (
        observed_relation is not None
        and observed_relation.lower() == str(declared_relation).lower()
    )
    if selection_identity == "differs" and not same_namespace:
        operands["r_c_containment"] = (
            "skipped: selection differs, boundary relation namespace changed"
        )
        return operands
    operands["r_c_containment"] = "failed"
    operands["r_c_containment_failure_is_in_declared_namespace"] = same_namespace
    return operands


def extract_candidate_boundary(
    cell: Mapping[str, Any],
    runner_sql: str,
    *,
    selected_template_id: Optional[str] = None,
    candidate_cost_vector: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Tuple[str, Dict[str, Any], Optional[Dict[str, Any]]]:
    """Boundary extraction per fidelity class (§6.2).  Never text-only.

    Y5 — **every refusal raised here carries the operands of the predicate it
    evaluated**, merged into the sealed receipt on catch: the verbatim
    ``runner_sql``, the extracted text that failed, both operands of the failed
    check, the observed and frozen template ids, the cost vector and the
    extraction proof.  A refusal that records only its own message is not
    attributable evidence: recovering the one text an auditor needed after
    ``CONTENT_BOUNDARY_V2`` cost a monkeypatch plus a full E10 session rebuild.
    """

    fidelity = cell["candidate"]["candidate_fidelity"]
    boundary = cell["boundary"]
    proof: Dict[str, Any] = {"fidelity": fidelity}
    rewrite: Optional[Dict[str, Any]] = None
    frozen_template = cell["frozen"]["selected_template_id"]

    def _refuse(message: str, boundary_sql: Optional[str] = None, **operands: Any):
        partial: Dict[str, Any] = {
            "candidate": {
                "acquisition": "replanned_selection_only",
                "candidate_fidelity": fidelity,
                "selected_template_id": selected_template_id,
                "frozen_selected_template_id": frozen_template,
                "selection_identity": (
                    None if selected_template_id is None
                    else ("same" if selected_template_id == frozen_template else "differs")
                ),
                "runner_sql": runner_sql,
                "runner_sql_digest": sha256_plain(runner_sql),
                "boundary_sql": boundary_sql,
                "boundary_sql_digest": (
                    sha256_plain(boundary_sql) if boundary_sql is not None else None
                ),
                "extraction_proof": dict(proof),
                "selection": {
                    "candidate_cost_vector": list(candidate_cost_vector or []),
                },
                "refusal_operands": dict(operands),
            },
            "refusal_stage": "boundary_extraction",
        }
        return ContentRefusal(message, partial=partial)

    if fidelity == "verbatim_subplan_planner_anchored":
        try:
            body, continuation = split_access_root(runner_sql)
        except Exception as exc:  # noqa: BLE001 - persist the operand, then refuse
            raise _refuse(
                "{}: access root could not be split: {}".format(cell["short_id"], exc),
                None,
                expected_wrapper="WITH caprls_access_root AS MATERIALIZED (",
                runner_sql_head=runner_sql[:200],
            )
        recomposed = (
            "WITH caprls_access_root AS MATERIALIZED (\n" + body + "\n)" + continuation
        )
        proof["recomposition_byte_identical"] = recomposed == runner_sql
        proof["extraction"] = "strict_core_sql"
        if not proof["recomposition_byte_identical"]:
            raise _refuse(
                "{}: access-root extraction is not byte-reversible".format(cell["short_id"]),
                body,
                recomposed_digest=sha256_plain(recomposed),
                runner_sql_digest=sha256_plain(runner_sql),
            )
        boundary_sql = body

    elif fidelity == "verbatim_subplan_text_anchored":
        cte = cell["candidate"]["cte_name"]
        proof["extraction"] = "named_cte_text"
        proof["cte_name"] = cte
        try:
            body = lift_named_cte(runner_sql, cte)
        except Exception as exc:  # noqa: BLE001 - persist the operand, then refuse
            raise _refuse(
                "{}: named CTE {!r} could not be lifted: {}".format(
                    cell["short_id"], cte, exc),
                None,
                declared_cte_name=cte,
                runner_sql_head=runner_sql[:200],
            )
        proof["substring_containment"] = body in runner_sql
        if not proof["substring_containment"]:
            raise _refuse(
                "{}: lifted CTE is not contained in the recomposed statement".format(
                    cell["short_id"]),
                body,
                declared_cte_name=cte,
            )
        boundary_sql = body.strip()

    elif fidelity == "re_rendered_projection":
        statement = runner_sql
        if cell["family"] == "E2":
            marker = "SELECT count(*)"
            if marker not in statement:
                raise _refuse(
                    "{}: E2 runner SQL carries no count(*) statement to re-render".format(
                        cell["short_id"]),
                    None,
                    expected_marker=marker,
                    runner_sql_head=runner_sql[:200],
                )
            statement = statement[statement.index(marker):].strip().rstrip(";")
        rewrite_kind = cell["candidate"]["rewrite_kind"]
        proof["extraction"] = "re_render_projection"
        try:
            if rewrite_kind == "select_list_only":
                boundary_sql, rewrite = rewrite_select_list(
                    statement.strip(), boundary["candidate_projection_sql"]
                )
            elif rewrite_kind == "select_list_and_continuation_strip":
                boundary_sql, rewrite = strip_ordered_limit_continuation(
                    statement, boundary["candidate_relation"],
                    boundary["candidate_projection_sql"],
                )
            else:
                raise _refuse(
                    "{}: unknown rewrite kind {!r}".format(cell["short_id"], rewrite_kind),
                    None,
                    declared_rewrite_kind=rewrite_kind,
                )
        except ContentRefusal as exc:
            # `rewrite_select_list` refuses when the rewrite touched more than the
            # select list; re-raise it carrying the operands (Y5).
            if getattr(exc, "partial", None):
                raise
            raise _refuse(
                "{}: {}".format(cell["short_id"], exc),
                None,
                declared_rewrite_kind=rewrite_kind,
                declared_projection=boundary["candidate_projection_sql"],
                statement_under_rewrite=statement.strip(),
            )
        proof["frozen_original_digest"] = sha256_plain(statement.strip())
        proof["rewritten_digest"] = sha256_plain(boundary_sql)
    else:
        raise _refuse(
            "unknown candidate_fidelity: {}".format(fidelity), None,
            declared_candidate_fidelity=fidelity,
        )

    # Y4.1 — the selection comparison is resolved BEFORE the containment
    # assertion is allowed to mean anything, and the assertion is namespace-aware.
    selection_identity = (
        None if selected_template_id is None
        else ("same" if selected_template_id == frozen_template else "differs")
    )
    proof["selection_identity_at_extraction"] = selection_identity
    proof["selected_template_id"] = selected_template_id
    proof["frozen_selected_template_id"] = frozen_template
    containment = evaluate_r_c_containment(cell, boundary_sql, selection_identity)
    proof.update(containment)
    if containment["r_c_containment"] == "failed":
        raise _refuse(
            "{}: extracted boundary does not contain the declared r_c {!r}".format(
                cell["short_id"], containment["declared_r_c"]
            ),
            boundary_sql,
            **containment
        )
    return boundary_sql, proof, rewrite


# --- E3 -------------------------------------------------------------------
class _E3Session:
    """Option B selection for E3, mirroring ``e3_sigmod_preview._prepare_cell_live``.

    Precedent for taking only the selection result:
    ``e3_sigmod_preview.py:466-525``.  Selection is
    ``prospective_explain_and_catalog_cost_only`` with
    ``measured_runtime_used_for_selection: False``; nothing here measures time.
    """

    def __init__(self, root: Path, pg_env: Any, manifest_path: Path) -> None:
        from caprls_core import e3_main as e3

        with Path(manifest_path).open("r", encoding="utf-8") as handle:
            self.manifest = yaml.safe_load(handle) or {}
        self.root = Path(root)
        self.pg_env = pg_env
        self.e3 = e3
        self.ranker = e3._ranker_from_manifest(self.root, self.manifest)
        self.registry = e3._e3_registry_from_manifest(self.manifest)
        scale_check = self.manifest.get("scale_check") or {}
        self.access_root_materialized = (
            str(scale_check.get("bound_runner_wrapper", "materialized")) == "materialized"
        )
        self.scale_by_dataset = {
            str(item.get("name")): str(item.get("scale", "reduced"))
            for item in self.manifest.get("datasets", ())
            if isinstance(item, Mapping)
        }
        self.seed_by_dataset = {
            str(item.get("name")): int(item.get("seed", 42))
            for item in self.manifest.get("datasets", ())
            if isinstance(item, Mapping)
        }
        self.tpch_scale = self.scale_by_dataset.get("tpch", "")
        self.job_scale = self.scale_by_dataset.get("job", "")
        # Prepare the E3 data in its isolated experiment database.
        self.pg_version = e3._prepare_database(
            self.root, pg_env, tpch_scale=self.tpch_scale, job_scale=self.job_scale
        )

    def candidate(self, cell: Mapping[str, Any]) -> CandidateBoundary:
        from caprls_core import e3_sigmod_preview as preview

        e3 = self.e3
        query = next(q for q in e3.QUERIES if q.query_id == cell["query_id"])
        policy = next(p for p in e3.POLICY_CONFIGS if p.config_id == cell["policy_id"])
        with _E3CostVectorCapture(e3) as capture:
            prepared = preview._prepare_cell_live(
                query=query,
                policy=policy,
                modes=(ADMISSION_FIRST_MODE,),
                pg_env=self.pg_env,
                ranker=self.ranker,
                registry=self.registry,
                dataset_scale=self.scale_by_dataset.get(query.workload, ""),
                seed=self.seed_by_dataset.get(query.workload, 42),
                pg_version=self.pg_version,
                access_root_materialized=self.access_root_materialized,
            )
        cost_vector = capture.vector()
        spec = prepared.modes[0].spec
        if spec is None:
            raise ContentRefusal(
                "{}: E3 selection produced no runner".format(cell["short_id"]),
                partial={"refusal_operands": {
                    "selected_template_id": prepared.selected_template_id,
                    "frozen_selected_template_id": cell["frozen"]["selected_template_id"],
                    "prepared_modes": [m.mode for m in prepared.modes],
                    "candidate_cost_vector": cost_vector,
                }},
            )
        runner_sql = spec.sql
        # Y4.1 — the observed template is resolved BEFORE extraction, so the
        # selection-identity comparison is the first thing decided and the
        # containment assertion knows whether it is still in-namespace.
        boundary_sql, proof, rewrite = extract_candidate_boundary(
            cell, runner_sql,
            selected_template_id=prepared.selected_template_id,
            candidate_cost_vector=cost_vector,
        )
        proof["strict_core_sql_digest"] = sha256_canonical_json(
            {"strict_core_sql": boundary_sql}
        )
        proof["selected_runner_digest_recomputed"] = sha256_canonical_json(
            {"exact_runner_sql": runner_sql}
        )
        if proof["selected_runner_digest_recomputed"] != prepared.selected_runner_digest:
            raise ContentRefusal(
                "{}: recomputed runner digest differs from the planner's".format(
                    cell["short_id"]
                ),
                partial={"refusal_operands": {
                    "recomputed_digest": proof["selected_runner_digest_recomputed"],
                    "planner_digest": prepared.selected_runner_digest,
                    "selected_template_id": prepared.selected_template_id,
                    "runner_sql": runner_sql,
                    "candidate_cost_vector": cost_vector,
                }},
            )
        return CandidateBoundary(
            selected_template_id=prepared.selected_template_id,
            selected_plan_id=prepared.selected_plan_id,
            selected_runner_digest=prepared.selected_runner_digest,
            runner_sql=runner_sql,
            boundary_sql=boundary_sql,
            prospective_total_cost=prepared.prospective_total_cost,
            predicate_text=e3._policy_predicate(query, policy),
            extraction_proof=proof,
            rewrite_diff=rewrite,
            candidate_cost_vector=cost_vector,
            cost_vector_source=(
                "passive pass-through observation of e3_main._verify_e3_static's "
                "EXPLAIN document during _prepare_cell_live; e3_main.py unmodified"
            ),
        )


# --- E2 -------------------------------------------------------------------
class _E2Session:
    """Option B selection for E2, mirroring ``e2_main.run_e2_main``'s derivation.

    §5.4 hygiene: the matview is built **once per family run**, not once per
    grid point.  Rebuilding it moments before each comparison would make the
    check trivially true.
    """

    def __init__(self, root: Path, pg_env: Any, manifest_path: Path) -> None:
        from caprls_core import e2_main, e2_smoke
        from caprls_core.oracle_audit import (
            _load_context,
            _load_policy,
            _render_exact_predicate,
        )
        from caprls_core.postgres_runner import run_psql_command

        with Path(manifest_path).open("r", encoding="utf-8") as handle:
            self.manifest = yaml.safe_load(handle) or {}
        self.root = Path(root)
        self.pg_env = pg_env
        self.e2_main = e2_main
        self.e2_smoke = e2_smoke
        self.context_id = "ctx_000001"
        applications = self.manifest.get("policy_applications") or [{}]
        self.policy_id = str(applications[0].get("policy_id", "tenant_group"))
        policy = _load_policy(self.root, self.policy_id)
        self.context = _load_context(self.context_id, pg_env)
        self.user_id = str(self.context["user_id"])
        self.ctx_hash = run_psql_command(
            "SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {};".format(
                quote_literal(self.context_id)
            ),
            pg_env,
        ).strip()
        # The live call to the shared renderer.  §5.4 correction (I-4b): the
        # frozen E2 record contains no predicate, so reconciliation is
        # necessarily re-implementation vs a live render, and
        # `reference_renderer_shared_with_candidate: false` holds at the
        # rendered-text level only.
        self.exact_predicate = _render_exact_predicate(
            str(policy["exact_sql_template"]), "d", "doc_id", self.context, "document"
        )
        guard_template = policy.get("guard_sql_template")
        if not guard_template:
            raise ContentRefusal(
                "E2 policy has no guard template",
                partial={"refusal_operands": {
                    "policy_id": self.policy_id,
                    "policy_keys": sorted(policy),
                }},
            )
        self.guard_predicate = _render_exact_predicate(
            str(guard_template), "d", "doc_id", self.context, "document"
        )
        self.total_rows = int(
            run_psql_command("SELECT count(*) FROM public.document;", pg_env)
        )
        self.authorized_rows = int(
            run_psql_command(
                "SELECT count(*) FROM public.document d WHERE {};".format(
                    self.exact_predicate
                ),
                pg_env,
            )
        )
        self.artifact_id = "auth_idx_doc_ctx_000001"
        self.keyed_artifact_id = "auth_idx_keyed_doc_ctx_000001"
        self.mav_artifact_id = "mav_document_ctx_000001"
        self.points = {p.point_id: p for p in e2_main._grid_points(self.manifest)}
        self._artifacts_built: set = set()
        self.artifact_build_epoch = datetime.now(timezone.utc).isoformat()
        self.matview_definition_digest = sha256_plain(
            e2_smoke._build_auth_view_sql(self.exact_predicate)
        )

    def _ensure_artifacts(self, availability: str) -> None:
        if availability in self._artifacts_built:
            return
        self.e2_main._build_artifacts(
            pg_env=self.pg_env,
            artifact_availability=availability,
            artifact_id=self.artifact_id,
            keyed_artifact_id=self.keyed_artifact_id,
            mav_artifact_id=self.mav_artifact_id,
            policy_id=self.policy_id,
            user_id=self.user_id,
            ctx_hash=self.ctx_hash,
            exact_predicate=self.exact_predicate,
        )
        self._artifacts_built.add(availability)

    def candidate(self, cell: Mapping[str, Any]) -> CandidateBoundary:
        e2_main = self.e2_main
        e2_smoke = self.e2_smoke
        point = self.points[cell["grid_point"]]
        self._ensure_artifacts(point.artifact_availability)
        hi = max(1, int(self.total_rows * point.s_q))
        lo = 1
        artifact_cardinality = e2_main._artifact_cardinalities(
            self.pg_env, self.artifact_id, self.keyed_artifact_id,
            point.artifact_availability,
        )[3]
        runner_sql_by_template: Dict[str, str] = {}
        for template in e2_smoke.TEMPLATE_CANDIDATES:
            sql_artifact_id = (
                self.keyed_artifact_id
                if template.template_id == "strong_auth_index_keyed_v1"
                else self.artifact_id
            )
            runner_sql_by_template[template.template_id] = e2_smoke._candidate_sql(
                template.template_id, self.exact_predicate, self.guard_predicate,
                lo, hi, sql_artifact_id, self.policy_id, self.user_id, self.ctx_hash,
            )
        template_id, payload = e2_main._prospective_admission_first_plan(
            policy_id=self.policy_id,
            total_rows=self.total_rows,
            authorized_rows=self.authorized_rows,
            artifact_availability=point.artifact_availability,
            artifact_cardinality=artifact_cardinality,
            point=point,
            exact_predicate=self.exact_predicate,
            guard_predicate=self.guard_predicate,
            lo=lo,
            hi=hi,
            artifact_id=self.artifact_id,
            keyed_artifact_id=self.keyed_artifact_id,
            mav_relation=self.mav_artifact_id,
            user_id=self.user_id,
            ctx_hash=self.ctx_hash,
            runner_sql_by_template=runner_sql_by_template,
            pg_env=self.pg_env,
        )
        runner_sql = runner_sql_by_template[template_id]
        e2_costs = [
            {"template_id": t, "prospective_total_cost": None,
             "note": "E2 planner payload exposes no per-template cost"}
            for t in payload.get("prospective_costed_template_ids", ())
        ]
        boundary_sql, proof, rewrite = extract_candidate_boundary(
            cell, runner_sql,
            selected_template_id=template_id,
            candidate_cost_vector=e2_costs,
        )
        proof["artifact_build_epoch"] = self.artifact_build_epoch
        proof["matview_definition_digest"] = self.matview_definition_digest
        cost = payload.get("chosen_pg_total_cost")
        # E2's planner payload exposes the costed template set and the chosen
        # cost, but not a per-template cost map; record exactly what exists
        # rather than implying a vector the payload does not carry.
        return CandidateBoundary(
            selected_template_id=template_id,
            selected_plan_id=payload.get("selected_plan_id"),
            selected_runner_digest=sha256_plain(runner_sql),
            runner_sql=runner_sql,
            boundary_sql=boundary_sql,
            prospective_total_cost=float(cost) if cost is not None else None,
            predicate_text=self.exact_predicate,
            extraction_proof=proof,
            rewrite_diff=rewrite,
            candidate_cost_vector=e2_costs,
            cost_vector_source=(
                "e2_main planner payload: prospective_costed_template_ids + "
                "chosen_pg_total_cost (no per-template cost map exists)"
            ),
        )


# --- E10 ------------------------------------------------------------------
def _assessment_payload(assessment: Any) -> Any:
    """Render an E10 artifact-state assessment as receipt-safe JSON (Z5-3)."""

    if assessment is None:
        return None
    if hasattr(assessment, "to_dict"):
        try:
            return assessment.to_dict()
        except Exception:  # noqa: BLE001 - fall through to the generic form
            pass
    import dataclasses

    if dataclasses.is_dataclass(assessment):
        return json.loads(json.dumps(dataclasses.asdict(assessment), default=str))
    if isinstance(assessment, (list, tuple)):
        return [_assessment_payload(item) for item in assessment]
    return str(assessment)


class _E10Session:
    """Option B selection for E10, mirroring
    ``e10_study._prepare_postgres_measurements`` (:12398-12606) and
    ``_prepare_e10_case_postgres_measurements`` (:11934-12130), stopping at the
    planner invocation.  The timed loop is never entered.

    ``results/raw/E10_PROTOCOL`` is a stale campaign; only
    ``SIGMOD_CURRENT_E10`` is pinned, and the frozen ``implementation.git_commit``
    is asserted by the spec (§2.1 trap).
    """

    def __init__(self, root: Path, pg_env: Any, manifest_path: Path) -> None:
        from caprls_core import e10_study as e10
        from caprls_core.native_rls import configure_native_rls
        from caprls_core.oracle_audit import _load_context, _load_policy
        from caprls_core.postgres_runner import run_psql_command

        with Path(manifest_path).open("r", encoding="utf-8") as handle:
            self.manifest = yaml.safe_load(handle) or {}
        self.root = Path(root)
        self.pg_env = pg_env
        self.e10 = e10
        self.context_id = "ctx_000001"
        self.context = _load_context(self.context_id, pg_env)
        self.user_id = str(self.context["user_id"])
        target_context, _alternate = e10._load_e10_state_contexts(self.context_id, pg_env)
        self.ctx_hash = str(target_context["ctx_hash"])
        self.context_version = int(target_context["version"])
        if e10._canonical_digest(self.context) != self.ctx_hash:
            raise ContentRefusal(
                "E10 planning context semantic digest mismatch",
                partial={"refusal_operands": {
                    "context_id": self.context_id,
                    "recomputed_digest": e10._canonical_digest(self.context),
                    "recorded_ctx_hash": self.ctx_hash,
                }},
            )
        self.policies = {
            policy_id: _load_policy(self.root, policy_id)
            for policy_id in ("tenant_group", "tenant_only_ticket", "purpose_region_invoice")
        }
        self.targets = sorted({e10._target_for_case(case) for case in e10.CASES})
        self.exact: Dict[Tuple[str, str], str] = {}
        for relname, rid_col, policy_id, alias in self.targets:
            self.exact[(relname, alias)] = e10._render_policy_predicate(
                str(self.policies[policy_id]["exact_sql_template"]),
                alias=alias, rid_col=rid_col, context=self.context, relname=relname,
            )
        for relname, _rid_col, _policy_id, alias in self.targets:
            configure_native_rls(
                rel="public.{}".format(relname),
                policy_name="caprls_e10_policy_{}".format(relname),
                predicate=e10._native_rls_policy_predicate(
                    self.exact[(relname, alias)], alias
                ),
                role_name=e10.E10_NATIVE_RLS_ROLE,
                pg_env=pg_env,
            )
        self.artifact_ids: Dict[str, Dict[str, str]] = {}
        self.artifact_rows: Dict[str, Dict[str, int]] = {}
        self.build_ms: Dict[str, Dict[str, float]] = {}
        self.storage_bytes: Dict[str, Dict[str, int]] = {}
        self.base_rows: Dict[str, int] = {}
        for relname, rid_col, policy_id, alias in self.targets:
            rel_exact = self.exact[(relname, alias)]
            ids = e10._artifact_ids_for_context(relname, self.context_id)
            self.artifact_ids[relname] = ids
            self.build_ms[relname] = {
                "auth": e10._timed_sql_script(
                    e10._build_auth_idx_sql(ids["auth"], policy_id, self.user_id,
                                            self.ctx_hash, relname, rid_col, alias,
                                            rel_exact), pg_env),
                "keyed": e10._timed_sql_script(
                    e10._build_keyed_sql(ids["keyed"], policy_id, self.user_id,
                                         self.ctx_hash, relname, rid_col, alias,
                                         rel_exact), pg_env),
                "mav": e10._timed_sql_script(
                    e10._build_mav_sql(ids["mav"], policy_id, self.ctx_hash, relname,
                                       rid_col, alias, rel_exact, self.context_id),
                    pg_env),
            }
            self.storage_bytes[relname] = {
                "auth": e10._relation_size_bytes("public.auth_idx", pg_env),
                "keyed": e10._relation_size_bytes("public.auth_idx_keyed", pg_env),
                "mav": e10._relation_size_bytes(
                    "public.{}".format(e10._mav_table(relname, self.context_id)), pg_env),
            }
            self.artifact_rows[relname] = {
                "auth": e10._run_count(
                    "SELECT count(*) FROM public.auth_idx WHERE artifact_id = {};".format(
                        quote_literal(ids["auth"])), pg_env),
                "keyed": e10._run_count(
                    "SELECT count(*) FROM public.auth_idx_keyed WHERE artifact_id = {};".format(
                        quote_literal(ids["keyed"])), pg_env),
                "mav": e10._run_count(
                    "SELECT count(*) FROM public.{};".format(
                        e10._mav_table(relname, self.context_id)), pg_env),
            }
            self.base_rows[relname] = e10._run_count(
                "SELECT count(*) FROM public.{};".format(relname), pg_env)
        self.artifact_validation_sql: Dict[str, List[str]] = {}
        # The epoch reads below go through the package's own private executor.
        self.content_pg_env = ContentPostgresEnv(
            host=pg_env.host, port=pg_env.port, user=pg_env.user,
            database=pg_env.database,
        )
        # Z5-1/Z5-3/Z5-4 bookkeeping.
        self.restored_cells: List[str] = []
        self.last_restoration: Any = None
        self.last_restoration_evidence: Optional[Dict[str, Any]] = None
        self.fingerprint_recheck: Optional[Dict[str, Any]] = None
        self.negative_state_cells = [
            case.query_id for case in e10.CASES
            if case.query_id in e10.E10_NEGATIVE_STATE_KIND_BY_QUERY
        ]

    def _live_epochs(self) -> Dict[str, Dict[str, int]]:
        """Read the three epoch counters the freshness predicate compares against."""

        from caprls_core.content_psql import run_command

        epochs: Dict[str, Dict[str, int]] = {}
        for kind, table, key in (
            ("base", "base_versions", "relname"),
            ("membership", "membership_versions", "scope_name"),
            ("context_scope", "context_versions", "ctx_hash"),
        ):
            raw = run_command(
                "SELECT {key} || '=' || version FROM public.{table} ORDER BY 1".format(
                    key=key, table=table
                ),
                self.content_pg_env,
            )
            values: Dict[str, int] = {}
            for line in raw.splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                name, _, version = line.rpartition("=")
                values[name] = int(version)
            epochs[kind] = values
        return epochs

    def _artifact_freshness_evidence(
        self, artifact_ids: Mapping[str, str]
    ) -> Dict[str, Any]:
        """Z5-2 — pair every dependency's `version_at_build` with the live epoch.

        The freshness predicate that decides `usable` compares exactly these two
        numbers.  Recording the pair turns a categorical "artifact unusable"
        into an attributable operand, and lets a leak be blamed on the cell that
        caused it rather than on the cell that first observes it.
        """

        from caprls_core.content_psql import quote_literal as _q, run_command

        ids = sorted(set(artifact_ids.values()))
        if not ids:
            return {"dependencies": [], "live_epochs": {}, "artifact_ids": []}
        epochs = self._live_epochs()
        raw = run_command(
            "SELECT artifact_id || '|' || dep_kind || '|' || dep_name || '|' "
            "|| version_at_build FROM public.artifact_dependencies "
            "WHERE artifact_id IN ({}) ORDER BY 1".format(
                ", ".join(_q(value) for value in ids)
            ),
            self.content_pg_env,
        )
        dependencies: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            artifact_id, dep_kind, dep_name, version = line.split("|", 3)
            live = epochs.get(dep_kind, {}).get(dep_name)
            built = int(version)
            dependencies.append({
                "artifact_id": artifact_id,
                "dep_kind": dep_kind,
                "dep_name": dep_name,
                "version_at_build": built,
                "live_version": live,
                "fresh": live is None or live == built,
            })
        return {
            "artifact_ids": ids,
            "live_epochs": epochs,
            "dependencies": dependencies,
            "stale_count": sum(1 for d in dependencies if not d["fresh"]),
        }

    def candidate(self, cell: Mapping[str, Any]) -> CandidateBoundary:
        e10 = self.e10
        case = next(c for c in e10.CASES if c.query_id == cell["query_id"])
        relname, rid_col, policy_id, alias = e10._target_for_case(case)
        rel_exact = self.exact[(relname, alias)]
        complete_guard = (
            e10._complete_guard_predicate(case, alias, rid_col, self.context, relname)
            if case.complete_guard_sql_template is not None
            else None
        )
        filter_sql = e10._e10_planning_query_predicate(case, alias, rid_col)
        case_artifact_ids = dict(self.artifact_ids[relname])
        mav_physical_relation = "public.{}".format(
            e10._mav_table(relname, self.context_id)
        )
        mav_dependency_profile = "legacy5"
        case_artifact_rows = dict(self.artifact_rows[relname])
        case_build_ms = dict(self.build_ms[relname])
        case_storage_bytes = dict(self.storage_bytes[relname])
        # Z5-2 — assert the epoch invariant BEFORE materializing anything, so a
        # leak from an earlier cell is attributed to that cell and not to this
        # one.  A mismatch this cell did not create is a cross-cell state leak
        # and refuses loudly; the artifact is never silently excluded, which is
        # what turned this into a three-round investigation.
        freshness_pre = self._artifact_freshness_evidence(case_artifact_ids)
        stale_pre = [d for d in freshness_pre["dependencies"] if not d["fresh"]]
        if stale_pre:
            raise ContentRefusal(
                "{}: cross-cell state leak — {} artifact dependenc(ies) were already "
                "stale before this cell materialized anything".format(
                    cell["short_id"], len(stale_pre)
                ),
                partial={"refusal_operands": {
                    "artifact_freshness_evidence": freshness_pre,
                    "stale_dependencies": stale_pre,
                    "created_by_this_cell": False,
                    "diagnosis": (
                        "an earlier negative-state cell advanced an epoch and did not "
                        "restore it; see e10_study.py:12591 and memo Y3.1/Z5-1"
                    ),
                }},
            )

        negative_handle = None
        if case.query_id in e10.E10_NEGATIVE_STATE_KIND_BY_QUERY:
            negative_handle = e10._materialize_e10_negative_state(
                self.root, case, self.context_id, self.pg_env
            )
            case_artifact_ids["mav"] = negative_handle.spec.artifact_id
            mav_physical_relation = negative_handle.spec.physical_relation
            mav_dependency_profile = "state9"
            _qualified, mav_table = e10._e10_planning_sql_relation(mav_physical_relation)
            case_artifact_rows["mav"] = e10._run_count(
                "SELECT count(*) FROM public.{};".format(mav_table), self.pg_env)
            case_build_ms["mav"] = 0.0
            case_storage_bytes["mav"] = e10._relation_size_bytes(
                mav_physical_relation, self.pg_env)

        try:
            return self._candidate_inner(
                cell=cell, case=case, relname=relname, rid_col=rid_col,
                policy_id=policy_id, alias=alias, rel_exact=rel_exact,
                complete_guard=complete_guard, filter_sql=filter_sql,
                case_artifact_ids=case_artifact_ids,
                case_artifact_rows=case_artifact_rows,
                case_build_ms=case_build_ms,
                case_storage_bytes=case_storage_bytes,
                mav_physical_relation=mav_physical_relation,
                mav_dependency_profile=mav_dependency_profile,
                negative_handle=negative_handle,
                freshness_pre=freshness_pre,
            )
        finally:
            # Z5-1 — restore through the FROZEN path, mirroring
            # e10_study.py:12591, and do it in `finally`: a refusal or an
            # exception must not leak the advanced epoch into later cells.
            # That leak is exactly how CONTENT_BOUNDARY_V2 poisoned every
            # document cell after Q10.
            if negative_handle is not None:
                restoration = e10._restore_e10_negative_state(
                    negative_handle, self.pg_env
                )
                self.last_restoration = restoration
                self.restored_cells.append(cell["short_id"])
                # Z5-3 — restoration proof, surfaced rather than assumed.  The
                # frozen helper already raises unless catalog, data and
                # assessment all recover exactly; these are its receipts.
                self.last_restoration_evidence = {
                    "cell": cell["short_id"],
                    "restored_catalog_state_digest":
                        restoration.restored_catalog_state_digest,
                    "pre_catalog_state_digest": restoration.pre_catalog_state_digest,
                    "restored_baseline_digest": restoration.restored_baseline_digest,
                    "baseline_digest": restoration.baseline_digest,
                    "catalog_exact": restoration.catalog_exact,
                    "data_exact": restoration.data_exact,
                    "assessment_exact": restoration.assessment_exact,
                    "restored_assessment": _assessment_payload(
                        restoration.restored_assessment
                    ),
                    "epochs_after_restore": self._live_epochs(),
                }

    def _candidate_inner(
        self, *, cell, case, relname, rid_col, policy_id, alias, rel_exact,
        complete_guard, filter_sql, case_artifact_ids, case_artifact_rows,
        case_build_ms, case_storage_bytes, mav_physical_relation,
        mav_dependency_profile, negative_handle, freshness_pre,
    ) -> CandidateBoundary:
        e10 = self.e10
        expectation = e10._e10_planning_expectation(
            root=self.root, case=case, context_id=self.context_id, context=self.context,
            context_hash=self.ctx_hash, context_version=self.context_version,
            policy=self.policies[policy_id], exact_predicate=rel_exact,
            guard_predicate=complete_guard, query_predicate=filter_sql,
            artifact_ids=case_artifact_ids, mav_physical_relation=mav_physical_relation,
            mav_dependency_profile=mav_dependency_profile, scope="fixture",
        )
        observation, collector_sql_digest = e10._collect_e10_planning_catalog_observation(
            expectation, self.pg_env
        )
        receipt = e10._issue_e10_planning_receipt(
            expectation, observation, collector_sql_digest=collector_sql_digest
        )
        replay = e10._replay_e10_planning_receipt(
            receipt, expectation, require_production=False
        )
        if not replay.valid:
            raise ContentRefusal(
                "E10 catalog observation failed before costing: " + ";".join(replay.reasons),
                partial={"refusal_operands": {
                    "replay_reasons": list(replay.reasons),
                    "collector_sql_digest": collector_sql_digest,
                    "query_id": cell["query_id"],
                }},
            )
        bundle = e10._issue_e10_admission_bundle(
            root=self.root, case=case, receipt=receipt, expectation=expectation,
            require_production=False,
        )
        admission_replay = e10._replay_e10_admission_bundle(
            bundle, root=self.root, case=case, receipt=receipt, expectation=expectation,
            require_production=False,
        )
        if not admission_replay.valid:
            raise ContentRefusal(
                "E10 typed admission failed before costing: "
                + ";".join(admission_replay.reasons),
                partial={"refusal_operands": {
                    "admission_replay_reasons": list(admission_replay.reasons),
                    "query_id": cell["query_id"],
                }},
            )
        filtered_rows = e10._run_count(
            "SELECT count(*) FROM public.{} {} WHERE {};".format(relname, alias, filter_sql),
            self.pg_env,
        )
        artifacts = e10._artifact_metadata_for_case(
            case, relname, rid_col, case_artifact_ids, case_artifact_rows,
            case_build_ms, case_storage_bytes, planning_receipt=receipt,
            planning_expectation=expectation, require_production_receipt=False,
        )
        assessment_by_kind = {item.kind: item for item in receipt.artifact_assessments}

        def _receipt_allows_template(template_id: str) -> bool:
            required = e10._required_artifact_for_template(template_id)
            if required is None:
                return True
            assessment = assessment_by_kind.get(required)
            return bool(assessment is not None and assessment.usable)

        # v2.3 clause B — the per-candidate cost vector, captured in our own
        # closure: E10 hands the costing function in, so nothing needs observing.
        cost_vector: List[Dict[str, Any]] = []

        def _case_explain_cost(template_id: str):
            if (
                e10._template_unavailable_reason(case, template_id) is not None
                or not _receipt_allows_template(template_id)
            ):
                cost_vector.append(
                    {"template_id": template_id, "prospective_total_cost": None,
                     "excluded": "template_unavailable_or_artifact_unusable"}
                )
                return None
            sql = e10._sql_for_template(
                case, template_id, relname, rid_col, alias, rel_exact,
                case_artifact_ids, policy_id, self.user_id, self.ctx_hash,
                self.context_id, complete_guard_predicate=complete_guard,
                mav_physical_relation=mav_physical_relation,
            )
            observed = e10._prospective_pg_cost(sql, self.pg_env)
            try:
                cost_vector.append(
                    {"template_id": template_id,
                     "prospective_total_cost": float(observed[0]),
                     "runner_sql_digest": sha256_plain(sql)}
                )
            except Exception:  # noqa: BLE001 - observation must never perturb planning
                pass
            return observed

        invocation = e10._planner_invocation_for_case(
            case, ADMISSION_FIRST_MODE, relname=relname, rid_col=rid_col,
            policy_id=policy_id, artifacts=artifacts,
            base_rows=self.base_rows[relname], filtered_rows=filtered_rows,
            alias=alias, exact_predicate=rel_exact,
            complete_guard_predicate=complete_guard, query_predicate=filter_sql,
            planning_receipt=receipt, planning_expectation=expectation,
            planning_admission_bundle=bundle, require_production_receipt=False,
            root=self.root, artifact_relations={"mav": mav_physical_relation},
            explain_cost_fn=_case_explain_cost,
        )
        choice = e10._plan_choice(invocation.occurrence_result)
        if choice is None:
            raise ContentRefusal(
                "{}: E10 planner chose no template".format(cell["short_id"]),
                partial={"refusal_operands": {
                    "frozen_selected_template_id": cell["frozen"]["selected_template_id"],
                    "candidate_cost_vector": sorted(
                        cost_vector, key=lambda i: str(i.get("template_id"))),
                    "artifact_ids": dict(case_artifact_ids),
                    "mav_physical_relation": mav_physical_relation,
                }},
            )
        template_id, _alternative = choice
        runner_sql = e10._sql_for_mode(
            case, ADMISSION_FIRST_MODE, relname, rid_col, alias, rel_exact,
            case_artifact_ids, policy_id, self.user_id, self.ctx_hash,
            plan_result=invocation.occurrence_result, context_id=self.context_id,
            complete_guard_predicate=complete_guard,
            mav_physical_relation=mav_physical_relation,
        )
        boundary_sql, proof, rewrite = extract_candidate_boundary(
            cell, runner_sql,
            selected_template_id=template_id,
            candidate_cost_vector=sorted(
                cost_vector, key=lambda i: str(i.get("template_id"))
            ),
        )
        proof["mav_physical_relation"] = mav_physical_relation
        proof["artifact_ids"] = dict(case_artifact_ids)
        # Z5-2 — the epoch operands, on every E10 receipt.
        proof["artifact_freshness_evidence"] = freshness_pre
        proof["artifact_assessments"] = [
            {
                "kind": item.kind,
                "usable": bool(getattr(item, "usable", False)),
                "fresh": bool(getattr(item, "fresh", False)),
                "reasons": list(getattr(item, "reasons", ()) or ()),
            }
            for item in getattr(receipt, "artifact_assessments", ())
        ]
        if negative_handle is not None:
            # Z5-3 — restoration is evidenced, not assumed.  The restore runs in
            # the caller's `finally`, so the proof is attached there.
            proof["negative_state"] = {
                "kind": e10.E10_NEGATIVE_STATE_KIND_BY_QUERY.get(case.query_id),
                "artifact_id": negative_handle.spec.artifact_id,
                "physical_relation": negative_handle.spec.physical_relation,
                "baseline_digest": negative_handle.baseline_digest,
                "restoration_pending_in_finally": True,
            }
        cost = None
        chosen = (invocation.query_plan or {}).get("production_chosen_cost")
        if isinstance(chosen, Mapping):
            cost = chosen.get("prospective_total_cost")
        return CandidateBoundary(
            selected_template_id=template_id,
            selected_plan_id=None,
            selected_runner_digest=sha256_canonical_json({"runner_sql": runner_sql}),
            runner_sql=runner_sql,
            boundary_sql=boundary_sql,
            prospective_total_cost=float(cost) if cost is not None else None,
            predicate_text=(
                complete_guard
                if cell["boundary"]["kind"] == "guard_candidate_not_exact"
                else rel_exact
            ),
            extraction_proof=proof,
            rewrite_diff=rewrite,
            candidate_cost_vector=sorted(
                cost_vector, key=lambda i: str(i.get("template_id"))
            ),
            cost_vector_source="captured in the harness's own explain_cost_fn closure",
        )


# ===========================================================================
# D. Reference side (§5.2) — isolated child process
# ===========================================================================
def invoke_reference(
    root: Path, cell: Mapping[str, Any], spec_path: Path, pg_env: ContentPostgresEnv
) -> Dict[str, Any]:
    """Spawn ``python -m caprls_core.content_reference`` and record its module list."""

    needs_context = cell["family"] in {"E2", "E10"}
    argv = [
        sys.executable, "-m", "caprls_core.content_reference",
        "--cell", cell["cell_id"], "--root", str(root),
        "--spec", str(spec_path), "--emit-sql",
    ]
    if needs_context:
        argv.append("--with-context")
    env = os.environ.copy()
    env.update(
        {
            "PGHOST": pg_env.host,
            "PGPORT": str(pg_env.port),
            "PGUSER": pg_env.user,
            "PGDATABASE": pg_env.database,
            "PYTHONPATH": str(root) + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    proc = subprocess.run(argv, cwd=str(root), env=env, text=True, capture_output=True)
    if proc.returncode not in (0, 2) or not proc.stdout.strip():
        raise ContentRefusal(
            "reference generator failed for {}: {}".format(cell["short_id"], proc.stderr[-2000:]),
            partial={"refusal_operands": {
                "argv": argv, "returncode": proc.returncode,
                "stderr_tail": proc.stderr[-2000:], "stdout_tail": proc.stdout[-2000:],
            }},
        )
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if payload.get("status") != "ok":
        raise ContentRefusal(
            "reference generator refused {}: {}".format(
                cell["short_id"], payload.get("error")
            ),
            partial={"refusal_operands": {
                "reference_error": payload.get("error"),
                "reference_error_type": payload.get("error_type"),
                "argv": argv,
            }},
        )
    offenders = [
        name
        for name in payload["independence"]["resident_modules"]
        if re.match(payload["independence"]["assertion_pattern"], name)
    ]
    if offenders:
        raise ContentRefusal(
            "reference process reported forbidden modules: " + ", ".join(offenders),
            partial={"refusal_operands": {
                "forbidden_modules": offenders,
                "assertion_pattern": payload["independence"]["assertion_pattern"],
                "resident_module_count": payload["independence"]["resident_module_count"],
            }},
        )
    return payload


def reconcile_predicate_text(
    cell: Mapping[str, Any], reference_text: str, candidate_text: Optional[str]
) -> str:
    """§5.4 T1 — dual rendering with text reconciliation; ``differs`` refuses."""

    if candidate_text is None:
        return "unavailable"
    if " ".join(reference_text.split()) == " ".join(candidate_text.split()):
        return "equal"
    return "differs"


# ===========================================================================
# E. Single-transaction execution (§8)
# ===========================================================================
def _tagged(name: str, expression: str) -> str:
    return "SELECT '{marker}{name}:' || ({expr});".format(
        marker=MARKER, name=name, expr=expression
    )


def _assert_statement(name: str, condition: str) -> str:
    """A SQL-level, fail-closed assertion.  Division by zero aborts the script."""

    return (
        "SELECT '{marker}assert_{name}:' || (1 / (CASE WHEN ({cond}) THEN 1 ELSE 0 END))"
        "::text;".format(marker=MARKER, name=name, cond=condition)
    )


def _digest_expression(table: str) -> str:
    """§8.2 phase 1 — byte-identical to ``canonical_result_from_row_texts``.

    ``octet_length`` is the byte length (matching ``len(row.encode('utf-8'))``),
    ``lpad(to_hex(...),16,'0')`` reproduces ``%016x``, and ``ORDER BY j COLLATE
    "C"`` is byte order over UTF-8, which coincides with Python's code-point
    ``sorted()``.  ``COALESCE`` makes the empty relation digest ``sha256("")``,
    exactly as the Python primitive does for an empty row sequence.
    """

    return (
        "(SELECT 'sha256:' || encode(sha256(convert_to(COALESCE(string_agg("
        "lpad(to_hex(octet_length(j)), 16, '0') || ':' || j, '' ORDER BY j COLLATE \"C\""
        "), ''), 'UTF8')), 'hex') "
        "FROM (SELECT to_jsonb(r)::text AS j FROM {table} r) s)".format(table=table)
    )


def _bag_difference_expression() -> str:
    """§8.2 phase 2 — deterministic grouping on ``bytea`` (V2-6).

    ``bytea`` equality is byte equality unconditionally, independent of
    collation determinism.
    """

    return (
        "(WITH a AS (SELECT convert_to(to_jsonb(r)::text, 'UTF8') AS k, count(*) AS n "
        "            FROM {actual} r GROUP BY 1), "
        "      b AS (SELECT convert_to(to_jsonb(r)::text, 'UTF8') AS k, count(*) AS n "
        "            FROM {reference} r GROUP BY 1), "
        "      d AS (SELECT COALESCE(a.k, b.k) AS k, COALESCE(a.n, 0) AS an, "
        "                   COALESCE(b.n, 0) AS bn "
        "            FROM a FULL OUTER JOIN b ON a.k = b.k) "
        " SELECT jsonb_build_object("
        "   'actual_only_rows', COALESCE(sum(GREATEST(an - bn, 0)), 0), "
        "   'reference_only_rows', COALESCE(sum(GREATEST(bn - an, 0)), 0), "
        "   'actual_only_witnesses', (SELECT COALESCE(jsonb_agg(w), '[]'::jsonb) FROM "
        "      (SELECT convert_from(k, 'UTF8') AS w FROM d WHERE an > bn ORDER BY k "
        "       LIMIT {cap}) wa), "
        "   'reference_only_witnesses', (SELECT COALESCE(jsonb_agg(w), '[]'::jsonb) FROM "
        "      (SELECT convert_from(k, 'UTF8') AS w FROM d WHERE bn > an ORDER BY k "
        "       LIMIT {cap}) wb))::text "
        " FROM d)".format(actual=ACTUAL_TABLE, reference=REFERENCE_TABLE, cap=WITNESS_CAP)
    )


def build_transaction_script(
    cell: Mapping[str, Any],
    candidate_sql: str,
    reference_sql: str,
    policy_cardinality_sql: str,
    *,
    crossvalidate: bool,
) -> str:
    """The whole §8.1 protocol: one psql invocation, one transaction, both sides."""

    protected_rel = cell["boundary"]["reference_relation"].split(".")[-1]
    guc_lines = "\n".join(render_pinned_guc(name, value) for name, value in PINNED_GUCS)
    guc_names = ", ".join(quote_literal(name.lower()) for name, _ in PINNED_GUCS)
    parts: List[str] = [
        "BEGIN ISOLATION LEVEL REPEATABLE READ;",
        guc_lines,
        _tagged(
            "snapshot",
            "jsonb_build_object("
            "'snapshot_token', pg_current_snapshot()::text, "
            "'current_user', current_user, "
            "'pg_version', current_setting('server_version'), "
            "'isolation', current_setting('transaction_isolation'))::text",
        ),
        # F2 — ``pg_settings.name`` is canonical-cased for DateStyle,
        # IntervalStyle and TimeZone, so a case-sensitive ``name IN (…)`` filter
        # matched only 13 of 16 and refused every cell.  Filter and aggregate on
        # ``lower(name)`` so the receipt's keys are stable across servers.
        _tagged(
            "gucs",
            "(SELECT jsonb_object_agg(lower(name), setting)::text FROM pg_settings "
            "WHERE lower(name) IN ({}))".format(guc_names),
        ),
        # §8.4 — RLS-bypass assertion.  E3 mutates the *global* RLS policy per
        # cell; if the executing role were RLS-subject, the reference reading
        # public.<rel> directly would be silently filtered and both sides would
        # be wrong together.
        _assert_statement(
            "rls_bypass",
            "(SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_roles "
            "WHERE rolname = current_user)",
        ),
        _tagged(
            "role",
            "(SELECT jsonb_build_object('rolsuper', rolsuper, 'rolbypassrls', rolbypassrls, "
            "'row_security', current_setting('row_security'), 'current_user', current_user)::text "
            "FROM pg_roles WHERE rolname = current_user)",
        ),
        _tagged(
            "policy_state_pre",
            "(SELECT count(*)::text FROM pg_policies WHERE schemaname = 'public' "
            "AND tablename = {})".format(quote_literal(protected_rel)),
        ),
        "CREATE TEMP TABLE {} ON COMMIT DROP AS\n{};".format(
            ACTUAL_TABLE, candidate_sql.rstrip().rstrip(";")
        ),
        "CREATE TEMP TABLE {} ON COMMIT DROP AS\n{};".format(
            REFERENCE_TABLE, reference_sql.rstrip().rstrip(";")
        ),
        # §8.2 — refuse a non-deterministic collation on any compared text column.
        _assert_statement(
            "deterministic_collations",
            "(SELECT count(*) = 0 FROM pg_attribute a "
            "JOIN pg_class c ON c.oid = a.attrelid "
            "LEFT JOIN pg_collation col ON col.oid = a.attcollation "
            "WHERE c.relnamespace = pg_my_temp_schema() "
            "AND c.relname IN ({actual}, {reference}) "
            "AND a.attnum > 0 AND NOT a.attisdropped AND a.attcollation <> 0 "
            "AND col.collisdeterministic IS DISTINCT FROM true)".format(
                actual=quote_literal(ACTUAL_TABLE), reference=quote_literal(REFERENCE_TABLE)
            ),
        ),
        # §8.3 — live column-contract validation, both sides.
        _tagged(
            "columns",
            "(SELECT jsonb_agg(jsonb_build_object("
            "'table', table_name, 'ordinal', ordinal_position, 'name', column_name, "
            "'data_type', data_type, 'is_nullable', is_nullable) "
            "ORDER BY table_name, ordinal_position)::text "
            "FROM information_schema.columns "
            "WHERE table_schema = (SELECT nspname FROM pg_namespace "
            "                      WHERE oid = pg_my_temp_schema()) "
            "AND table_name IN ({actual}, {reference}))".format(
                actual=quote_literal(ACTUAL_TABLE), reference=quote_literal(REFERENCE_TABLE)
            ),
        ),
        _tagged(
            "row_counts",
            "jsonb_build_object("
            "'candidate_row_count', (SELECT count(*) FROM {actual}), "
            "'reference_row_count', (SELECT count(*) FROM {reference}))::text".format(
                actual=ACTUAL_TABLE, reference=REFERENCE_TABLE
            ),
        ),
        # §9.2 — companion query making the pre-registered upper bound checkable.
        _tagged(
            "policy_cardinality",
            "({})::text".format(policy_cardinality_sql.rstrip().rstrip(";")),
        ),
        _tagged("candidate_digest", _digest_expression(ACTUAL_TABLE)),
        _tagged("reference_digest", _digest_expression(REFERENCE_TABLE)),
        _tagged("bag_difference", _bag_difference_expression()),
        # Diagnostic only; never gates (§10.1).
        _tagged(
            "ordered_sequence_match",
            "(WITH a AS (SELECT row_number() OVER () AS i, to_jsonb(r)::text AS j "
            "            FROM {actual} r), "
            "      b AS (SELECT row_number() OVER () AS i, to_jsonb(r)::text AS j "
            "            FROM {reference} r) "
            " SELECT (NOT EXISTS (SELECT 1 FROM a FULL OUTER JOIN b USING (i) "
            "                     WHERE a.j IS DISTINCT FROM b.j))::text)".format(
                actual=ACTUAL_TABLE, reference=REFERENCE_TABLE
            ),
        ),
    ]
    if crossvalidate:
        for name, table in (("rows_actual", ACTUAL_TABLE), ("rows_reference", REFERENCE_TABLE)):
            parts.append(
                _tagged(
                    name,
                    "(SELECT CASE WHEN (SELECT count(*) FROM {table}) <= {cap} "
                    "THEN (SELECT COALESCE(jsonb_agg(to_jsonb(r)::text), '[]'::jsonb) "
                    "      FROM {table} r)::text ELSE NULL END)".format(
                        table=table, cap=CROSSVALIDATION_ROW_THRESHOLD
                    ),
                )
            )
    parts.append(
        _tagged(
            "policy_state_post",
            "(SELECT count(*)::text FROM pg_policies WHERE schemaname = 'public' "
            "AND tablename = {})".format(quote_literal(protected_rel)),
        )
    )
    parts.append("COMMIT;")
    return "\n".join(parts) + "\n"


#: A command tag is an uppercase verb, optionally followed by uppercase words
#: and/or counts.  No tagged value can match it: counts are digits, digests
#: start with ``sha256:``, JSON starts with ``{`` or ``[``, and booleans are
#: lowercase ``t``/``f``.
_PSQL_COMMAND_VERBS = frozenset(
    {
        "ALTER", "ANALYZE", "BEGIN", "CALL", "CHECKPOINT", "CLOSE", "CLUSTER",
        "COMMENT", "COMMIT", "COPY", "CREATE", "DEALLOCATE", "DECLARE", "DELETE",
        "DISCARD", "DO", "DROP", "EXECUTE", "EXPLAIN", "FETCH", "GRANT", "IMPORT",
        "INSERT", "LISTEN", "LOAD", "LOCK", "MERGE", "MOVE", "NOTIFY", "PREPARE",
        "REASSIGN", "REFRESH", "REINDEX", "RELEASE", "RESET", "REVOKE", "ROLLBACK",
        "SAVEPOINT", "SECURITY", "SELECT", "SET", "SHOW", "START", "TRUNCATE",
        "UNLISTEN", "UPDATE", "VACUUM",
    }
)
_PSQL_COMMAND_TAG_RE = re.compile(r"^[A-Z][A-Z0-9 ]*$")


def is_psql_command_tag(line: str) -> bool:
    """True when a line is a psql command-status echo rather than a value."""

    stripped = line.strip()
    if not stripped or _PSQL_COMMAND_TAG_RE.fullmatch(stripped) is None:
        return False
    return stripped.split()[0] in _PSQL_COMMAND_VERBS


#: Found by gate-hardening v2 on its first live run, in the same parse layer as
#: F7: the ``ordered_sequence_match`` tag casts a boolean with ``::text``, which
#: yields ``true``/``false`` — **not** psql's ``t``/``f`` display form.  The old
#: comparison ``value.strip() == "t"`` was therefore *always* ``False``, so every
#: receipt would have carried a wrong diagnostic regardless of the truth.  It
#: never gates (§10.1), but a field that is unconditionally false must not ship.
_TRUE_TEXTS = frozenset({"t", "true", "y", "yes", "on", "1"})
_FALSE_TEXTS = frozenset({"f", "false", "n", "no", "off", "0"})


def parse_bool_text(value: str, label: str) -> bool:
    """Parse a PostgreSQL boolean in either display form, fail-closed."""

    token = str(value).strip().lower()
    if token in _TRUE_TEXTS:
        return True
    if token in _FALSE_TEXTS:
        return False
    raise ContentRefusal(
        "{} is not a boolean: {!r}".format(label, str(value)[:80]),
        partial={"refusal_operands": {
            "label": label, "observed_value": str(value)[:200],
            "accepted_true": sorted(_TRUE_TEXTS), "accepted_false": sorted(_FALSE_TEXTS),
        }},
    )


def parse_tagged_output(raw: str) -> Dict[str, str]:
    """Content-boundary verification helper."""

    values: Dict[str, str] = {}
    noise: List[str] = []
    unexpected: List[str] = []
    for line in raw.splitlines():
        if line.startswith(MARKER):
            name, _, rest = line[len(MARKER):].partition(":")
            if name in values:
                unexpected.append("duplicate tag: " + name)
                continue
            values[name] = rest
        elif not line.strip():
            continue
        elif is_psql_command_tag(line):
            noise.append(line.strip())
        else:
            unexpected.append(line)
    if unexpected:
        raise ContentRefusal(
            "transaction output carried {} unrecognised line(s); refusing rather "
            "than absorbing them into a tag value: {!r}".format(
                len(unexpected), unexpected[:5]
            ),
            partial={"refusal_operands": {
                "unrecognised_lines": unexpected[:40],
                "unrecognised_count": len(unexpected),
                "command_tags_dropped": noise[:40],
                "tags_parsed": sorted(values),
            }},
        )
    values["__noise__"] = json.dumps(noise, separators=(",", ":"))
    return values


# ===========================================================================
# F. Per-cell verification
# ===========================================================================
def _column_contract(cell: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"ordinal": c["ordinal"], "name": c["name"], "data_type": c["data_type"]}
        for c in cell["boundary"]["columns"]
    ]


def validate_columns(cell: Mapping[str, Any], observed: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """§8.3 — two different comparisons (V2-4).

    ``(ordinal, name, data_type)`` is compared against the declared contract on
    **both** sides; ``is_nullable`` is compared **candidate versus reference
    only**, never against the contract, because ``CREATE TEMP TABLE ... AS``
    does not propagate ``NOT NULL`` and E3's contracts declare
    ``nullable: false`` throughout — comparing it to the contract would refuse
    every cell on the first run.
    """

    contract = _column_contract(cell)
    by_table: Dict[str, List[Mapping[str, Any]]] = {}
    for row in observed:
        by_table.setdefault(row["table"], []).append(row)
    for table in (ACTUAL_TABLE, REFERENCE_TABLE):
        rows = sorted(by_table.get(table, []), key=lambda r: r["ordinal"])
        got = [
            {"ordinal": r["ordinal"], "name": r["name"], "data_type": r["data_type"]}
            for r in rows
        ]
        if got != contract:
            raise ContentRefusal(
                "boundary_column_contract_violation on {}: {} != declared {}".format(
                    table, got, contract
                ),
                partial={"refusal_operands": {
                    "table": table, "observed_columns": got,
                    "declared_columns": contract,
                }},
            )
    actual_rows = sorted(by_table[ACTUAL_TABLE], key=lambda r: r["ordinal"])
    reference_rows = sorted(by_table[REFERENCE_TABLE], key=lambda r: r["ordinal"])
    if [r["name"] for r in actual_rows] != [r["name"] for r in reference_rows]:
        raise ContentRefusal(
            "boundary_column_contract_violation: name sets differ",
            partial={"refusal_operands": {
                "candidate_column_names": [r["name"] for r in actual_rows],
                "reference_column_names": [r["name"] for r in reference_rows],
            }},
        )
    nullable_actual = [r["is_nullable"] for r in actual_rows]
    nullable_reference = [r["is_nullable"] for r in reference_rows]
    if nullable_actual != nullable_reference:
        raise ContentRefusal(
            "boundary_column_contract_violation: is_nullable differs side vs side",
            partial={"refusal_operands": {
                "candidate_is_nullable": nullable_actual,
                "reference_is_nullable": nullable_reference,
                "compared_against_contract": False,
            }},
        )
    return {
        "columns": contract,
        "column_contract_digest": sha256_plain(
            json.dumps(contract, sort_keys=True, separators=(",", ":"))
        ),
        "is_nullable_side_vs_side": nullable_actual,
        "is_nullable_compared_against_contract": False,
    }


def crossvalidate_python(
    rows_actual: Optional[Sequence[str]],
    rows_reference: Optional[Sequence[str]],
    server_digests: Tuple[str, str],
    server_diff: Tuple[int, int],
) -> Dict[str, Any]:
    """Run the audited Python path and assert **digest** equality (V2-5).

    Reuses ``canonical_result_from_row_texts`` and ``_bag_difference``
    unmodified; the in-DB encoding is byte-identical to them, so this is no
    longer "the two paths agree on counts" but "the two paths agree on the
    digest".
    """

    if rows_actual is None or rows_reference is None:
        return {"crossvalidated": False, "reason": "row_count_above_threshold"}
    from caprls_core.e3_sigmod_preview import (
        _bag_difference,
        canonical_result_from_row_texts,
    )

    actual = canonical_result_from_row_texts(tuple(rows_actual))
    reference = canonical_result_from_row_texts(tuple(rows_reference))
    actual_only, reference_only = _bag_difference(actual, reference)
    digest_equal = (
        actual.result_digest == server_digests[0]
        and reference.result_digest == server_digests[1]
    )
    diff_equal = (actual_only, reference_only) == server_diff
    return {
        "crossvalidated": True,
        "crossvalidation_digest_equal": bool(digest_equal),
        "crossvalidation_diff_equal": bool(diff_equal),
        "python_candidate_digest": actual.result_digest,
        "python_reference_digest": reference.result_digest,
        "python_actual_only_rows": actual_only,
        "python_reference_only_rows": reference_only,
    }


# ===========================================================================
# G. Package driver
# ===========================================================================
@dataclass
class RunContext:
    """Content-boundary verification helper."""

    root: Path
    run_dir: Path
    spec_path: Path
    predeclared_path: Path
    spec: Mapping[str, Any]
    predeclared: Mapping[str, Any]
    #: v2.3 clause A — the pre-signed classification table.  The harness never
    #: self-classifies; this is the only intake for a human cause assignment.
    classification: Mapping[str, Any]
    identity: Dict[str, Any]
    pg_env_by_family: Mapping[str, ContentPostgresEnv]
    legacy_pg_env_by_family: Mapping[str, Any]

    def pg_env(self, family: str) -> ContentPostgresEnv:
        try:
            return self.pg_env_by_family[family]
        except KeyError:
            raise ContentVerifyError(
                "no database configured for family {}".format(family)
            )

    def legacy_pg_env(self, family: str) -> Any:
        try:
            return self.legacy_pg_env_by_family[family]
        except KeyError:
            raise ContentVerifyError(
                "no database configured for family {}".format(family)
            )


def _receipt_skeleton(cell: Mapping[str, Any], context: RunContext) -> Dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "cell_id": cell["cell_id"],
        "short_id": cell["short_id"],
        "family": cell["family"],
        "shape_class": cell["shape_class"],
        "query_id": cell["query_id"],
        "policy_id": cell["policy_id"],
        "dataset": dict(cell["dataset"]),
        "protocol": {
            "warmup": 0,
            "measured": 0,
            "timing_recorded": False,
            "outcome_feedback_to_selector": False,
            "measurement_protocol": "not_applicable/correctness_only",
            "serial": True,
        },
        # §7 — the four identity layers, per receipt: source, data, plan, harness.
        "identity": {
            "source_digest": context.identity["source"]["source_digest"],
            "source_file_list_digest": context.identity["source"]["source_file_list_digest"],
            "harness_digest": context.identity["harness"]["harness_digest"],
            "spec_digest": context.identity["spec_digest"],
            "predeclared_digest": context.identity["predeclared_digest"],
            "policy_manifest_digest": context.identity.get("policy_manifest_digest"),
            "git": context.identity["git"],
        },
    }


def observed_comparison_id(cell: Mapping[str, Any], observed_template: str) -> str:
    """v2.3 clause C — the comparison actually instantiated by this run.

    ``comparison_id`` is keyed to the *frozen* template, so a template flip does
    not instantiate the declared comparison.  Both are carried, and the density
    figures are published as ``declared -> observed``.
    """

    declared = cell["reference"]["comparison_id"]
    frozen = cell["frozen"]["selected_template_id"]
    if observed_template == frozen:
        return declared
    if declared.endswith("_x_" + frozen):
        return declared[: -len("_x_" + frozen)] + "_x_" + observed_template
    return declared + "@observed:" + observed_template


def _candidate_block(
    cell: Mapping[str, Any],
    candidate: "CandidateBoundary",
    selection_identity: str,
    runner_identity: Any,
    classification: Mapping[str, Any],
) -> Dict[str, Any]:
    """The observation side, built before any refusal can discard it (F8)."""

    block = {
        "acquisition": "replanned_selection_only",
        "candidate_fidelity": cell["candidate"]["candidate_fidelity"],
        "selected_template_id": candidate.selected_template_id,
        "selected_plan_id": candidate.selected_plan_id,
        "selected_runner_digest": candidate.selected_runner_digest,
        "frozen_selected_template_id": cell["frozen"]["selected_template_id"],
        "selection_identity": selection_identity,
        "selection_difference_cause": classification["selection_difference_cause"],
        "selection_classified_by": classification["classified_by"],
        "selection_admissible_observed_templates": classification[
            "admissible_observed_templates"
        ],
        "selection_evidence_ref": classification["evidence_ref"],
        "runner_identity": runner_identity.runner_identity,
        "runner_identity_detail": runner_identity.to_dict(),
        "context_source": "live_database" if cell["family"] != "E3" else None,
        "boundary_sql": candidate.boundary_sql,
        "boundary_sql_digest": sha256_plain(candidate.boundary_sql),
        "runner_sql": candidate.runner_sql,
        "frozen_runner_sql_hash": cell["frozen"]["runner_sql_digest"],
        "extraction_proof": candidate.extraction_proof,
        "rewrite_diff": candidate.rewrite_diff,
        "candidate_predicate_text": candidate.predicate_text,
        "candidate_predicate_text_source": cell["candidate"]["predicate_text_source"],
        "selection": {
            "method": "prospective_explain_and_catalog_cost_only",
            "measured_runtime_used_for_selection": False,
            "prospective_total_cost": candidate.prospective_total_cost,
            # v2.3 condition 3 — on EVERY receipt, not only on refusals.
            "candidate_cost_vector": candidate.candidate_cost_vector,
            "cost_vector_source": candidate.cost_vector_source,
        },
    }
    stability = classification.get("selection_stability")
    if stability:
        block["selection_stability"] = stability
    if candidate.candidate_cost_vector:
        costs = [
            item["prospective_total_cost"]
            for item in candidate.candidate_cost_vector
            if item.get("prospective_total_cost") is not None
        ]
        chosen = next(
            (
                item["prospective_total_cost"]
                for item in candidate.candidate_cost_vector
                if item["template_id"] == candidate.selected_template_id
                and item.get("prospective_total_cost") is not None
            ),
            None,
        )
        frozen_cost = next(
            (
                item["prospective_total_cost"]
                for item in candidate.candidate_cost_vector
                if item["template_id"] == cell["frozen"]["selected_template_id"]
                and item.get("prospective_total_cost") is not None
            ),
            None,
        )
        if chosen is not None and frozen_cost is not None and chosen > 0:
            block["selection"]["frozen_template_margin_pct"] = round(
                (frozen_cost - chosen) / chosen * 100.0, 4
            )
        block["selection"]["costed_candidates"] = len(costs)
    return block


def verify_cell(
    cell: Mapping[str, Any],
    context: RunContext,
    candidate_session: Any,
) -> Dict[str, Any]:
    """Run one cell end to end and return its receipt."""

    receipt = _receipt_skeleton(cell, context)
    if cell["frozen"]["selected_template_id"] in NATIVE_RLS_TEMPLATES:
        raise ContentRefusal(
            "{}: native-RLS selected template is refused (memo 8.4)".format(
                cell["short_id"]
            ),
            partial={
                **receipt,
                "refusal_operands": {
                    "frozen_selected_template_id": cell["frozen"][
                        "selected_template_id"
                    ],
                    "native_rls_templates": sorted(NATIVE_RLS_TEMPLATES),
                },
            },
        )

    candidate = candidate_session.candidate(cell)
    selection_identity = (
        "same"
        if candidate.selected_template_id == cell["frozen"]["selected_template_id"]
        else "differs"
    )
    runner_identity = falsify_head_replan(cell, candidate.runner_sql)

    # v2.3 clause A — classification enters only through the pre-signed table,
    # and only when the observed template is inside the declared admissible set.
    if selection_identity == "same":
        classification = {
            "selection_difference_cause": None,
            "classified_by": None,
            "admissible_observed_templates": None,
            "selection_stability": None,
            "evidence_ref": None,
        }
        for entry in context.classification.get("entries", ()):
            if entry["short_id"] == cell["short_id"]:
                classification["selection_stability"] = entry.get("selection_stability")
                classification["evidence_ref"] = entry["evidence_ref"]
                break
    else:
        classification = classify_selection_difference(
            context.classification, cell, candidate.selected_template_id
        )

    # F8 / clause D — the candidate block is populated *before* any refusal that
    # could follow, so a refusal carries the observation side rather than
    # discarding it.
    receipt["candidate"] = _candidate_block(
        cell, candidate, selection_identity, runner_identity, classification
    )
    # Z5-2 / Z5-3 — E10 artifact-lifecycle evidence, on the receipt.
    proof = candidate.extraction_proof or {}
    if proof.get("artifact_freshness_evidence") is not None:
        receipt["artifact_freshness_evidence"] = proof["artifact_freshness_evidence"]
    if proof.get("artifact_assessments"):
        receipt["artifact_assessments"] = proof["artifact_assessments"]
    evidence = getattr(candidate_session, "last_restoration_evidence", None)
    if evidence and evidence.get("cell") == cell["short_id"]:
        receipt["negative_state_restoration"] = evidence
    receipt["result"] = {
        "reference_relation_id": cell["reference"]["reference_relation_id"],
        "comparison_id": cell["reference"]["comparison_id"],
        "observed_comparison_id": observed_comparison_id(
            cell, candidate.selected_template_id
        ),
    }

    def _refuse(message: str, **operands: Any) -> ContentRefusal:
        """Y5 — every refuse condition persists the operands it evaluated."""

        partial = dict(receipt)
        partial["refusal_operands"] = dict(operands)
        return ContentRefusal(message, partial=partial)

    if candidate.selected_template_id in NATIVE_RLS_TEMPLATES:
        raise _refuse(
            "{}: selection produced a native-RLS mode".format(cell["short_id"]),
            selected_template_id=candidate.selected_template_id,
            native_rls_templates=sorted(NATIVE_RLS_TEMPLATES),
        )
    if classification["selection_difference_cause"] == "unknown":
        raise _refuse(
            "{}: selection differs with cause unknown "
            "(observed {!r}, frozen {!r}, {})".format(
                cell["short_id"], candidate.selected_template_id,
                cell["frozen"]["selected_template_id"], classification["classified_by"],
            ),
            observed_template=candidate.selected_template_id,
            frozen_template=cell["frozen"]["selected_template_id"],
            admissible_observed_templates=classification["admissible_observed_templates"],
            classified_by=classification["classified_by"],
            evidence_ref=classification["evidence_ref"],
            candidate_cost_vector=candidate.candidate_cost_vector,
            r_c_containment=candidate.extraction_proof.get("r_c_containment"),
            declared_candidate_relation=cell["boundary"]["candidate_relation"],
            observed_boundary_relation=candidate.extraction_proof.get(
                "observed_boundary_relation"),
        )

    family_pg_env = context.pg_env(cell["family"])
    reference = invoke_reference(context.root, cell, context.spec_path, family_pg_env)
    reconciliation = reconcile_predicate_text(
        cell, reference["reference_predicate_text"], candidate.predicate_text
    )
    if reconciliation == "differs":
        raise _refuse(
            "{}: predicate_text_reconciliation differs".format(cell["short_id"]),
            reference_predicate_text=reference["reference_predicate_text"],
            candidate_predicate_text=candidate.predicate_text,
            reference_predicate_digest=sha256_plain(
                str(reference["reference_predicate_text"])),
            candidate_predicate_digest=sha256_plain(str(candidate.predicate_text)),
            candidate_predicate_text_source=cell["candidate"]["predicate_text_source"],
        )

    script = build_transaction_script(
        cell,
        candidate.boundary_sql,
        reference["boundary_sql"],
        reference["policy_cardinality_sql"],
        crossvalidate=bool(cell["crossvalidate"]),
    )
    raw = run_script(script, family_pg_env)
    tagged = parse_tagged_output(raw)

    snapshot = json.loads(tagged["snapshot"])
    gucs = json.loads(tagged["gucs"])
    if gucs.get("client_encoding", "").upper() != "UTF8":
        raise _refuse(
            "{}: client_encoding is not UTF8".format(cell["short_id"]),
            observed_client_encoding=gucs.get("client_encoding"),
            expected="UTF8", gucs_read_back=sorted(gucs),
        )
    if len(gucs) != len(PINNED_GUCS):
        raise _refuse(
            "{}: expected {} pinned GUCs, observed {}".format(
                cell["short_id"], len(PINNED_GUCS), len(gucs)
            ),
            expected_gucs=sorted(name.lower() for name, _ in PINNED_GUCS),
            observed_gucs=sorted(gucs),
            missing=sorted({n.lower() for n, _ in PINNED_GUCS} - set(gucs)),
        )
    role = json.loads(tagged["role"])
    policy_state_pre = int(tagged["policy_state_pre"])
    policy_state_post = int(tagged["policy_state_post"])
    if policy_state_pre != policy_state_post:
        raise _refuse(
            "{}: pg_policies count changed during the cell".format(cell["short_id"]),
            policy_state_pre=policy_state_pre, policy_state_post=policy_state_post,
            protected_relation=cell["boundary"]["reference_relation"],
        )
    columns = validate_columns(cell, json.loads(tagged["columns"]))
    counts = json.loads(tagged["row_counts"])
    bag = json.loads(tagged["bag_difference"])
    candidate_digest = tagged["candidate_digest"]
    reference_digest = tagged["reference_digest"]
    policy_cardinality_observed = int(tagged["policy_cardinality"])

    rows_actual = None
    rows_reference = None
    if cell["crossvalidate"]:
        raw_actual = tagged.get("rows_actual", "")
        raw_reference = tagged.get("rows_reference", "")
        if raw_actual.strip():
            rows_actual = json.loads(raw_actual)
        if raw_reference.strip():
            rows_reference = json.loads(raw_reference)
    crossvalidation = crossvalidate_python(
        rows_actual,
        rows_reference,
        (candidate_digest, reference_digest),
        (int(bag["actual_only_rows"]), int(bag["reference_only_rows"])),
    )

    anchors = cell["anchors"]
    expected = anchors.get("expected_policy_cardinality")
    predeclared_cell = context.predeclared["cells"].get(cell["short_id"], {})
    if not predeclared_cell:
        raise _refuse(
            "{}: no pre-registration entry (memo 10.1 #8)".format(cell["short_id"]),
            looked_up_short_id=cell["short_id"],
            predeclared_digest=context.identity.get("predeclared_digest"),
            predeclared_cell_count=len(context.predeclared.get("cells", {})),
        )
    if predeclared_cell.get("cell_id") != cell["cell_id"]:
        raise _refuse(
            "{}: pre-registration cell_id does not match the spec".format(cell["short_id"]),
            predeclared_cell_id=predeclared_cell.get("cell_id"),
            spec_cell_id=cell["cell_id"],
        )
    # §9.1 — a deviation sets `expectation_deviation` and triggers attribution;
    # it never causes automatic failure and never aborts the package on its own.
    deviation = expected is not None and policy_cardinality_observed != int(expected)
    # §9.2 — `A_c subset of sigma_Pi(R)`, so the observed policy cardinality is
    # an upper bound on the boundary.  A diagnostic invariant, not a criterion.
    bound_holds = int(counts["candidate_row_count"]) <= policy_cardinality_observed

    vacuous = int(counts["candidate_row_count"]) == 0 and int(counts["reference_row_count"]) == 0

    # `receipt["candidate"]` was populated before the refusal points and must
    # survive this update untouched (F8).
    receipt.update(
        {
            "boundary": {
                "kind": cell["boundary"]["kind"],
                "relation": cell["boundary"]["reference_relation"],
                "candidate_relation": cell["boundary"]["candidate_relation"],
                "rid_col": cell["boundary"]["rid_col"],
                "alias": cell["boundary"]["reference_alias"],
                "columns": columns["columns"],
                "column_contract_digest": columns["column_contract_digest"],
                "is_nullable_side_vs_side": columns["is_nullable_side_vs_side"],
                "refinement": {
                    "r_c": cell["boundary"]["refinement"].get("r_c"),
                    "source": "spec",
                    "exception": cell["boundary"]["refinement"].get("exception"),
                },
            },
            "reference": {
                "generator": reference["generator"],
                "reference_authority": reference["reference_authority"],
                "independence": reference["independence"],
                "reference_predicate_text": reference["reference_predicate_text"],
                "predicate_text_reconciliation": reconciliation,
                "reference_renderer_shared_with_candidate": reference[
                    "reference_renderer_shared_with_candidate"
                ],
                "spec_digest": reference["spec_digest"],
                "policy_manifest_digest": reference["policy_manifest_digest"],
                "reference_generator_digest": reference["reference_generator_digest"],
                "executor": reference["executor"],
                "boundary_sql": reference["boundary_sql"],
                "boundary_sql_digest": reference["boundary_sql_digest"],
            },
            "result": {
                "candidate_row_count": int(counts["candidate_row_count"]),
                "reference_row_count": int(counts["reference_row_count"]),
                "candidate_digest": candidate_digest,
                "reference_digest": reference_digest,
                "digest_encoding": "canonical_row_texts_v1",
                "actual_only_rows": int(bag["actual_only_rows"]),
                "reference_only_rows": int(bag["reference_only_rows"]),
                "actual_only_witnesses": [],
                "reference_only_witnesses": [],
                "ordered_sequence_match": parse_bool_text(
                    tagged["ordered_sequence_match"], "ordered_sequence_match"
                ),
                "vacuous": vacuous,
                "discriminating_power": cell["labels"]["discriminating_power"],
                "enforcement_discriminating": cell["labels"]["enforcement_discriminating"],
                "reference_relation_id": cell["reference"]["reference_relation_id"],
                "comparison_id": cell["reference"]["comparison_id"],
                # v2.3 clause C — the comparison this run actually instantiated.
                "observed_comparison_id": observed_comparison_id(
                    cell, candidate.selected_template_id
                ),
            },
            "derived": {
                # I-N7: `boundary_cardinality` and `frozen_result_row_count` are
                # different quantities and are kept apart.  |A_c| is not recorded
                # in any frozen artefact; the frozen number is post-continuation
                # (post-LIMIT for Q7/Q10, post-DISTINCT for Q6).
                "boundary_cardinality": int(counts["candidate_row_count"]),
                "frozen_result_row_count": cell["frozen"]["frozen_result_row_count"],
                "boundary_cardinality_is_recorded_in_a_frozen_artifact": False,
                "continuation_scalar_actual": None,
                "continuation_scalar_frozen": cell["frozen"]["frozen_result_row_count"],
                "continuation_scalar_execution": "not_executed_read_only_package",
                "continuation_scalar_execution_reason": (
                    "the package performs no writes; E10 Q4's continuation invokes "
                    "public.unsafe_log, which inserts into public.udf_audit"
                ),
                "policy_cardinality_observed": policy_cardinality_observed,
                "policy_cardinality_bound_holds": bound_holds,
                "order_key_is_total": cell["labels"]["order_key_is_total"],
            },
            "snapshot": {
                "same_transaction": True,
                "isolation": "repeatable read",
                "snapshot_token": snapshot["snapshot_token"],
                "pg_version": snapshot["pg_version"],
                "gucs": gucs,
                "current_user": role["current_user"],
                "rolsuper": role["rolsuper"],
                "rolbypassrls": role["rolbypassrls"],
                "row_security": role["row_security"],
                "policy_state_digest": sha256_plain(
                    "{}:{}".format(cell["boundary"]["reference_relation"], policy_state_pre)
                ),
                "context_binding_digest": reference.get("context_binding_digest"),
                # F7 evidence: psql command-status lines seen despite --quiet.
                # Expected 0; any value > 0 means the parser dropped them as
                # noise rather than absorbing them into a tag value.
                "psql_command_tags_dropped": json.loads(tagged.get("__noise__", "[]")),
                # Clause B (v2.2-B): fingerprints are per family, computed at
                # that family's session start against that family's database.
                # The receipt references the family key; the block itself lives
                # once in identity.dataset_fingerprint_by_family.
                "database": family_pg_env.database,
                "dataset_fingerprint_ref": cell["family"],
                "dataset_fingerprint_digest": (
                    context.identity.get("dataset_fingerprint_by_family", {})
                    .get(cell["family"], {})
                    .get("fingerprint_digest")
                ),
                "statistics_digest": (
                    context.identity.get("statistics_digest_by_family", {})
                    .get(cell["family"])
                ),
            },
            "predeclaration": {
                "expected_policy_cardinality": expected,
                "anchor_kind": anchors["anchor_kind"],
                "anchor_source": anchors["anchor_source"],
                "expected_vacuous": predeclared_cell.get("expected_vacuous"),
                "expectation_deviation": bool(deviation)
                or (
                    predeclared_cell.get("expected_vacuous") is not None
                    and predeclared_cell.get("expected_vacuous") != vacuous
                ),
            },
        }
    )
    receipt["result"].update(
        {k: v for k, v in crossvalidation.items() if k != "reason"}
    )

    passed = (
        candidate_digest == reference_digest
        and receipt["result"]["actual_only_rows"] == 0
        and receipt["result"]["reference_only_rows"] == 0
        and receipt["result"]["candidate_row_count"]
        == receipt["result"]["reference_row_count"]
    )
    if cell["crossvalidate"] and crossvalidation.get("crossvalidated"):
        passed = passed and bool(crossvalidation.get("crossvalidation_digest_equal"))
        passed = passed and bool(crossvalidation.get("crossvalidation_diff_equal"))
    # The unknown-cause refusal now fires *before* the comparison (see above), so
    # a refused cell no longer pays for a transaction it cannot use.
    if not passed:
        receipt["result"]["actual_only_witnesses"] = bag.get("actual_only_witnesses", [])
        receipt["result"]["reference_only_witnesses"] = bag.get(
            "reference_only_witnesses", []
        )
        receipt["status"] = "fail"
        receipt["failure_reason"] = "boundary_multiset_difference"
    else:
        spec_digest_matches = (
            context.identity["spec_digest"] == context.predeclared["spec_digest"]
        )
        receipt["status"] = "pass" if spec_digest_matches else "pass_after_spec_revision"
        receipt["failure_reason"] = None
    return receipt


def run_package(
    root: Path,
    *,
    run_id: str,
    pg_env_by_family: Mapping[str, ContentPostgresEnv],
    spec_path: Optional[Path] = None,
    predeclared_path: Optional[Path] = None,
    classification_path: Optional[Path] = None,
    warmup: int = 0,
    measured: int = 0,
    only: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Run the whole package, fail-closed, serial, zero-timing.

    Clause A: ``pg_env_by_family`` routes each family to its own, already-built
    database.  This function never builds a database and never issues DDL: the
    per-family provisioning is a separate, explicit step
    (``content_cli provision``) run **before** the package starts, so that no
    builder can ever execute against another family's state.
    """

    if warmup != 0 or measured != 0:
        raise ContentVerifyError(
            "content-correctness requires warmup = measured = 0 "
            "(measurement_protocol: not_applicable/correctness_only)"
        )
    missing = sorted({"E2", "E3", "E10"} - set(pg_env_by_family))
    if missing and not only:
        raise ContentVerifyError(
            "per-family databases are required (memo v2.2 clause A); missing: "
            + ", ".join(missing)
        )
    databases = {env.database for env in pg_env_by_family.values()}
    if len(databases) != len(pg_env_by_family):
        raise ContentVerifyError(
            "each family requires its OWN database (memo v2.2 clause A); observed: "
            + json.dumps({k: v.database for k, v in sorted(pg_env_by_family.items())})
        )
    root = Path(root)
    spec_path = Path(spec_path) if spec_path else root / "specs" / "content_cells.yaml"
    spec = load_spec(spec_path)
    run_dir = root / "results" / "raw" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "receipts").mkdir(exist_ok=True)
    (run_dir / "failures").mkdir(exist_ok=True)

    predeclared_path = (
        Path(predeclared_path) if predeclared_path else run_dir / "predeclared_expectations.yaml"
    )
    if not predeclared_path.exists():
        raise ContentVerifyError(
            "pre-registration is missing; write predeclared_expectations.yaml before "
            "execution (memo 9.1)"
        )
    with predeclared_path.open("r", encoding="utf-8") as handle:
        predeclared = yaml.safe_load(handle)

    classification_path = (
        Path(classification_path)
        if classification_path
        else root / "specs" / "selection_difference_classification.yaml"
    )
    if not classification_path.exists():
        raise ContentVerifyError(
            "the pre-signed selection classification table is missing "
            "(memo v2.3 clause A); every selection difference would refuse"
        )
    classification = load_selection_classification(classification_path)

    audit = require_audit(root, spec_path)

    identity = {
        "source": source_identity(root),
        "harness": harness_identity(root),
        "git": git_identity(root),
        "spec_digest": _sha256_file(spec_path),
        "predeclared_digest": _sha256_file(predeclared_path),
        # v2.3 clause A — a NEW pre-signed input; its digest is recorded before
        # execution.  It does not touch spec_digest, so the pre-registration
        # carries forward unchanged.
        "selection_classification_digest": _sha256_file(classification_path),
        "selection_classification_path": str(
            classification_path.relative_to(root)
            if str(classification_path).startswith(str(root))
            else classification_path
        ),
        "policy_manifest_digest": _sha256_file(
            root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
        ),
        "implementation_fidelity_audit": audit,
        # Clause B — filled in per family at that family's session start, against
        # that family's database.  Never once per run against a shared database.
        "dataset_fingerprint_by_family": {},
        "statistics_digest_by_family": {},
        "database_by_family": {
            family: env.database for family, env in sorted(pg_env_by_family.items())
        },
        "database_topology": "per_family_database_same_cluster (memo v2.2 clause A)",
    }
    # §10.2 — the spec and the pre-registration are *copied* into the run
    # directory, not referenced.
    (run_dir / "content_cells.yaml").write_bytes(spec_path.read_bytes())
    (run_dir / "predeclared_expectations.copy.yaml").write_bytes(
        predeclared_path.read_bytes()
    )
    (run_dir / "selection_difference_classification.copy.yaml").write_bytes(
        classification_path.read_bytes()
    )

    from caprls_core.postgres_runner import PostgresEnv

    legacy_pg_env_by_family = {
        family: PostgresEnv(
            host=env.host, port=env.port, user=env.user, database=env.database
        )
        for family, env in pg_env_by_family.items()
    }
    context = RunContext(
        root=root, run_dir=run_dir, spec_path=spec_path,
        predeclared_path=predeclared_path, spec=spec, predeclared=predeclared,
        classification=classification, identity=identity,
        pg_env_by_family=pg_env_by_family,
        legacy_pg_env_by_family=legacy_pg_env_by_family,
    )

    cells = ordered_cells(spec)
    if only:
        wanted = set(only)
        cells = [c for c in cells if c["short_id"] in wanted or c["cell_id"] in wanted]

    sessions: Dict[str, Any] = {}
    manifests = {
        "E2": root / "manifests" / "experiments" / "e2_alternative_matrix_reduced.yaml",
        "E3": root / "manifests" / "experiments" / "e3_standard_sf1_rawpg.yaml",
        "E10": root / "manifests" / "experiments" / "e10_case_study.yaml",
    }
    factories = {"E2": _E2Session, "E3": _E3Session, "E10": _E10Session}

    receipts: List[Dict[str, Any]] = []
    status = "complete"
    failure: Optional[Dict[str, Any]] = None
    for cell in cells:
        family = cell["family"]
        try:
            if family not in sessions:
                sessions[family] = factories[family](
                    root, context.legacy_pg_env(family), manifests[family]
                )
                # Clause B — fingerprint this family's data state at ITS session
                # start, against ITS database, once.
                session = sessions[family]
                identity["dataset_fingerprint_by_family"][family] = dataset_fingerprint(
                    root,
                    context.pg_env(family),
                    family,
                    tpch_scale=getattr(session, "tpch_scale", ""),
                    job_scale=getattr(session, "job_scale", ""),
                )
                identity["statistics_digest_by_family"][family] = statistics_digest(
                    context.pg_env(family), family
                )
            receipt = verify_cell(cell, context, sessions[family])
            # Z5-4 — after the LAST negative-state cell, re-collect this family's
            # dataset fingerprint (or record that it is unchanged).  Q8/Q10 mutate
            # `document.payload` and delete a `group_membership` row; without the
            # restore those mutations persisted and the recorded data identity no
            # longer described the state the cells read.  With the restore in
            # place this must come back byte-identical — and it is checked, not
            # assumed.
            _recheck_fingerprint_after_negative_states(
                cell, context, sessions[family], root, identity
            )
        except ContentRefusal as exc:
            # F8 / v2.3 clause D — MERGE the partially-built receipt; do not
            # rebuild a bare skeleton.  For a selection refusal the discarded
            # material was exactly the attribution evidence, and §X2.2 shows it
            # cannot be reconstructed afterwards: the planner path is not
            # reproducible, so a later re-derivation yields a sample, not the
            # run's value.
            receipt = _receipt_skeleton(cell, context)
            if getattr(exc, "partial", None):
                for key, value in exc.partial.items():
                    if key not in ("status", "failure_reason"):
                        receipt[key] = value
                receipt["partial_receipt_merged"] = True
            receipt["status"] = "refused"
            receipt["failure_reason"] = str(exc)
            receipts.append(receipt)
            _write_receipt(run_dir, receipt)
            # Every stop class leaves attributable artefacts.
            _freeze_failure(run_dir, receipt)
            status = "refused"
            failure = {"cell_id": cell["cell_id"], "reason": str(exc)}
            break
        except BaseException as exc:  # noqa: BLE001 - Clause C, see below
            # Clause C (v2.2-C): any execution-time exception that is not a
            # ContentRefusal — psql errors, planner/loader PostgresErrors,
            # anything — is recorded as `refused` with
            # `harness_error:<class>:<message>` and follows the SAME
            # stop-package / summary / manifest / seal path.  **No failure class
            # may leave the run directory without sealed artefacts.**  Before
            # this clause an escaping ContentPsqlError bypassed build_summary,
            # write_manifest_and_merkle and _seal_run_directory entirely.
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            reason = "harness_error:{}:{}".format(type(exc).__name__, exc)
            receipt = _receipt_skeleton(cell, context)
            receipt["status"] = "refused"
            receipt["failure_reason"] = reason
            receipt["harness_error"] = {
                "class": type(exc).__name__,
                "module": type(exc).__module__,
                "message": str(exc)[:8000],
            }
            receipts.append(receipt)
            _write_receipt(run_dir, receipt)
            _freeze_failure(run_dir, receipt)
            status = "refused"
            failure = {"cell_id": cell["cell_id"], "reason": reason}
            break
        receipts.append(receipt)
        _write_receipt(run_dir, receipt)
        if receipt["status"] == "fail":
            _freeze_failure(run_dir, receipt)
            status = "incomplete_failed"
            failure = {
                "cell_id": cell["cell_id"],
                "reason": receipt["failure_reason"],
            }
            break

    return _finalize_run(
        run_dir=run_dir, spec=spec, receipts=receipts, identity=identity,
        status=status, failure=failure, run_id=run_id,
    )


def _finalize_run(
    *,
    run_dir: Path,
    spec: Mapping[str, Any],
    receipts: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    status: str,
    failure: Optional[Mapping[str, Any]],
    run_id: str,
) -> Dict[str, Any]:
    """Clause D (v2.2-D) — integrity computed exactly once, last, outside itself.

    Ordering, and the reason for each step:

    1. compute the seal record and write ``IMMUTABLE`` — so the seal is part of
       the covered file set rather than an afterthought;
    2. write ``summary.json`` **once**, already containing ``seal``;
    3. write ``summary.csv``;
    4. one ``write_manifest_and_merkle``, excluding both ``MANIFEST.sha256`` and
       ``INTEGRITY.json`` from the covered set;
    5. write ``INTEGRITY.json`` = ``{manifest_path, package_merkle_root, file_count}``;
    6. apply the read-only ``chmod`` **last**, and record ``readonly_applied`` by
       re-``stat``-ing a file, so a no-op filesystem is disclosed, not assumed.

    Result: exactly one ``package_merkle_root`` per run directory, reproducible
    from that directory.  The root is deliberately **not** written back into
    ``summary.json`` — that write-back is what created the irreproducible loop.
    """

    summary = build_summary(spec, receipts, identity, status, failure, run_id)
    if status != "complete":
        summary["seal"] = _write_seal_record(
            run_dir, failure["reason"] if failure else status
        )
    with (run_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    _write_summary_csv(run_dir, receipts)
    integrity = write_manifest_and_merkle(run_dir)
    if status != "complete":
        # chmod must be last, and the observation of whether it took effect can
        # only exist after it: so it lives in INTEGRITY.json, which is already
        # outside the covered set, rather than in a third sealed file.
        integrity["seal_observation"] = _apply_readonly(run_dir)
        summary["seal"].update(integrity["seal_observation"])
    with (run_dir / "INTEGRITY.json").open("w", encoding="utf-8") as handle:
        json.dump(integrity, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if status != "complete":
        _make_readonly(run_dir / "INTEGRITY.json")
    summary["integrity"] = integrity
    summary["integrity_note"] = (
        "package_merkle_root is persisted in INTEGRITY.json, which is excluded from "
        "the set it covers; it is NOT written back into summary.json. Reproduce it by "
        "re-running merkle_root over MANIFEST.sha256."
    )
    return summary


def _recheck_fingerprint_after_negative_states(
    cell: Mapping[str, Any],
    context: "RunContext",
    session: Any,
    root: Path,
    identity: Dict[str, Any],
) -> None:
    """Z5-4 — close the §7.2 data-identity hole the missing restore reopened.

    ``dataset_fingerprint`` is collected once per family at session start.  The
    negative-state cells mutate ``document.payload`` and delete a
    ``group_membership`` row; unrestored, the recorded E10 data identity stops
    describing the state the later cells read.  With Z5-1's restore in place the
    fingerprint must come back **byte-identical**, so it is re-collected and
    compared rather than assumed.
    """

    pending = getattr(session, "negative_state_cells", None)
    if not pending:
        return
    restored = getattr(session, "restored_cells", [])
    if len(restored) < len(pending):
        return
    if getattr(session, "fingerprint_recheck", None) is not None:
        return
    family = cell["family"]
    before = identity.get("dataset_fingerprint_by_family", {}).get(family, {})
    after = dataset_fingerprint(root, context.pg_env(family), family)
    unchanged = after.get("fingerprint_digest") == before.get("fingerprint_digest")
    changed_relations = sorted(
        name
        for name, digest in (after.get("content_digests") or {}).items()
        if (before.get("content_digests") or {}).get(name) != digest
    )
    recheck = {
        "family": family,
        "trigger": "after the last negative-state cell ({})".format(cell["short_id"]),
        "restored_cells": list(restored),
        "fingerprint_digest_at_session_start": before.get("fingerprint_digest"),
        "fingerprint_digest_after_restore": after.get("fingerprint_digest"),
        "unchanged": bool(unchanged),
        "changed_relations": changed_relations,
    }
    session.fingerprint_recheck = recheck
    identity.setdefault("dataset_fingerprint_recheck", {})[family] = recheck
    if not unchanged:
        raise ContentRefusal(
            "{}: {} dataset fingerprint changed across the negative-state cells; "
            "the recorded data identity would not describe the state the cells "
            "read".format(cell["short_id"], family),
            partial={"refusal_operands": recheck},
        )


def _write_receipt(run_dir: Path, receipt: Mapping[str, Any]) -> None:
    name = receipt["short_id"] + ".json"
    with (run_dir / "receipts" / name).open("w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _freeze_failure(run_dir: Path, receipt: Mapping[str, Any]) -> None:
    """§10.2 — freeze the failing receipt with witnesses and both SQL texts.

    The package **stops**: no later cells, no retry, no re-plan.  The summary is
    written ``incomplete_failed`` with partial counts and no ``52/52`` artefact
    is produced.  The run directory becomes immutable, and the spec and the
    pre-registration are *copied* into it, not referenced.
    """

    name = receipt["short_id"] + ".json"
    with (run_dir / "failures" / name).open("w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with (run_dir / "failures" / "ATTRIBUTION.md").open("w", encoding="utf-8") as handle:
        handle.write(_attribution_template(receipt))


def _write_seal_record(run_dir: Path, reason: str) -> Dict[str, Any]:
    """Clause D step 1 — write ``IMMUTABLE`` *before* the integrity block.

    The seal record must be part of the covered file set, not an afterthought
    appended to an in-memory dict that is never persisted.
    """

    marker = Path(run_dir) / "IMMUTABLE"
    with marker.open("w", encoding="utf-8") as handle:
        handle.write(
            "This run directory is sealed (memo 10.2, v2.2 clause C/D).\n"
            "reason: {}\n"
            "No later cell was run, nothing was retried, nothing was re-planned.\n"
            "No 52/52 artifact exists for this run.\n"
            "Any fix requires the pre-registration re-issued with a new digest;\n"
            "the prior one is retained forever.\n".format(reason)
        )
    return {
        "sealed": True,
        "reason": reason,
        "readonly_observation": "INTEGRITY.json#seal_observation",
    }


def _make_readonly(path: Path) -> None:
    import stat

    try:
        mode = Path(path).stat().st_mode
        Path(path).chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    except OSError:  # pragma: no cover - best effort
        pass


def _apply_readonly(run_dir: Path) -> Dict[str, Any]:
    """Clause D step 6 — chmod last, and **observe** whether it took effect.

    The previous implementation asserted a seal that silently did not seal: on
    the run volume every sealed ``summary.json`` was still ``-rwx------``.  A
    seal that does not seal must be disclosed, not assumed.
    """

    import stat

    sealed: List[str] = []
    for path in sorted(Path(run_dir).rglob("*")):
        if not path.is_file():
            continue
        try:
            mode = path.stat().st_mode
            path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        except OSError:
            continue
        sealed.append(str(path.relative_to(run_dir)))
    probe = Path(run_dir) / "summary.json"
    readonly_applied: Optional[bool] = None
    probe_mode: Optional[str] = None
    if probe.is_file():
        probe_mode = oct(probe.stat().st_mode & 0o777)
        readonly_applied = not os.access(str(probe), os.W_OK)
    return {
        "files_sealed": len(sealed),
        "readonly_applied": readonly_applied,
        "readonly_probe": "summary.json",
        "readonly_probe_mode": probe_mode,
        "readonly_note": (
            "observed by re-stat after chmod; a filesystem that ignores the mode "
            "change is disclosed here rather than assumed away"
        ),
    }


def _attribution_template(receipt: Mapping[str, Any]) -> str:
    return """# Stop attribution — {cell}

The package stopped at this cell.  No later cell was run, nothing was retried,
nothing was re-planned, and **no 52/52 artifact exists for this run**.

Each step below must produce a recorded artifact, in order (memo 10.2):

(a) Re-render both SQL texts from the frozen spec and diff them against the
    texts stored in this receipt.
(b) Evaluate `sigma_(Pi AND r)(R)` a **third** time with a hand-written
    statement, outside both generators, and paste it here verbatim.
(c) Classify **by (b)**, not by inspecting the planner:
    * witnesses subset of `sigma_Pi(R)` but not in the candidate
      => candidate under-approximates => planner finding, unfixable, publish;
    * witnesses not in `sigma_Pi(R)`
      => candidate over-approximates => planner finding, unfixable, publish;
    * witnesses disagree with (b)
      => reference or checker defect => fixable.
(d) Any fix requires the pre-registration re-issued with a new digest; the prior
    one is retained forever.

{evidence}
""".format(cell=receipt["short_id"], evidence=_attribution_evidence(receipt))


def _attribution_evidence(receipt: Mapping[str, Any]) -> str:
    """Render whatever observation side this stop class actually produced.

    F8 / v2.3 clause D: refusals are written to ``failures/`` with the same
    template as mismatches, so **every** stop class leaves an attributable
    artefact.  A refusal has no comparison, but it does have the selection
    evidence — and for a selection-difference refusal that evidence *is* the
    attribution.
    """

    lines: List[str] = []
    lines.append("status                        : {}".format(receipt.get("status")))
    lines.append("failure_reason                : {}".format(receipt.get("failure_reason")))
    candidate = receipt.get("candidate") or {}
    result = receipt.get("result") or {}
    reference = receipt.get("reference") or {}
    if candidate:
        selection = candidate.get("selection") or {}
        lines.append("")
        lines.append("-- selection (observation side, retained by F8) --")
        for label, value in (
            ("selected_template_id", candidate.get("selected_template_id")),
            ("frozen_selected_template_id", candidate.get("frozen_selected_template_id")),
            ("selection_identity", candidate.get("selection_identity")),
            ("selection_difference_cause", candidate.get("selection_difference_cause")),
            ("selection_classified_by", candidate.get("selection_classified_by")),
            ("selection_stability", candidate.get("selection_stability")),
            ("admissible_observed_templates",
             candidate.get("selection_admissible_observed_templates")),
            ("selected_plan_id", candidate.get("selected_plan_id")),
            ("selected_runner_digest", candidate.get("selected_runner_digest")),
            ("runner_identity", candidate.get("runner_identity")),
            ("prospective_total_cost", selection.get("prospective_total_cost")),
            ("frozen_template_margin_pct", selection.get("frozen_template_margin_pct")),
            ("candidate boundary SQL digest", candidate.get("boundary_sql_digest")),
        ):
            lines.append("{:<30}: {}".format(label, value))
        vector = selection.get("candidate_cost_vector") or []
        if vector:
            lines.append("")
            lines.append("-- per-candidate prospective cost vector --")
            lines.append("source: {}".format(selection.get("cost_vector_source")))
            for item in vector:
                lines.append(
                    "  {:<34} {}".format(
                        item.get("template_id"), item.get("prospective_total_cost")
                    )
                )
    if reference:
        lines.append("")
        lines.append("reference boundary SQL digest : {}".format(
            reference.get("boundary_sql_digest")))
    if "actual_only_rows" in result:
        lines.append("")
        lines.append("-- comparison --")
        lines.append("actual_only_rows              : {}".format(
            result.get("actual_only_rows")))
        lines.append("reference_only_rows           : {}".format(
            result.get("reference_only_rows")))
        lines.append("comparison_id (declared)      : {}".format(
            result.get("comparison_id")))
        lines.append("observed_comparison_id        : {}".format(
            result.get("observed_comparison_id")))
    else:
        lines.append("")
        lines.append("-- comparison --")
        lines.append("not reached: this cell stopped before or during the comparison")
        if result.get("observed_comparison_id"):
            lines.append("comparison_id (declared)      : {}".format(
                result.get("comparison_id")))
            lines.append("observed_comparison_id        : {}".format(
                result.get("observed_comparison_id")))
    if receipt.get("harness_error"):
        lines.append("")
        lines.append("-- harness error (not a verdict) --")
        lines.append(json.dumps(receipt["harness_error"], indent=2, sort_keys=True))
    return "\n".join(lines)


def _stop_class(status: str, failure: Optional[Mapping[str, Any]]) -> str:
    reason = str((failure or {}).get("reason") or "")
    if reason.startswith("harness_error:"):
        return "harness_error"
    if status == "refused":
        return "protocol_refusal"
    if status == "incomplete_failed":
        return "mismatch_verdict"
    return status


def build_summary(
    spec: Mapping[str, Any],
    receipts: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    status: str,
    failure: Optional[Mapping[str, Any]],
    run_id: str,
) -> Dict[str, Any]:
    """§10.1 — the honest denominators are in the headline, not a footnote."""

    completed = [r for r in receipts if r.get("status") in {"pass", "pass_after_spec_revision"}]
    declared = spec["denominators"]
    passes = len(completed)
    complete = status == "complete" and passes == 52
    fidelity = Counter(
        r["candidate"]["candidate_fidelity"] for r in completed if "candidate" in r
    )
    # v2.3 clause C — density is published as `declared -> observed`.  A template
    # flip does not instantiate the declared comparison, so the observed set is
    # recomputed from `observed_comparison_id` rather than assumed equal.
    observed_comparisons = {
        r["result"]["observed_comparison_id"]
        for r in completed
        if r.get("result", {}).get("observed_comparison_id")
    }
    observed_substantive = {
        r["result"]["observed_comparison_id"]
        for r in completed
        if r.get("result", {}).get("observed_comparison_id")
        and r["result"].get("enforcement_discriminating")
    }
    non_deterministic = sorted(
        r["short_id"]
        for r in completed
        if r["candidate"].get("selection_stability") == "non_deterministic"
    )
    headline = {
        "boundary_receipts": 52,
        "receipts_passed": passes,
        "exact_boundary_receipts": declared["exact_boundary_receipts"],
        "vacuous": sum(1 for r in completed if r["result"]["vacuous"]),
        "candidate_fidelity": dict(fidelity),
        # v2.3 clause B — a SINGLE-RUN OBSERVATION, never a package property,
        # and never to be improved by re-running.
        "selection_identity_same": "{}/52".format(
            sum(1 for r in completed if r["candidate"]["selection_identity"] == "same")
        ),
        "selection_identity_same_is_single_run_observation": True,
        "selection_identity_differs": sorted(
            r["short_id"]
            for r in completed
            if r["candidate"]["selection_identity"] == "differs"
        ),
        "selection_non_deterministic_cells": non_deterministic,
        "runner_identity_byte_identical": "{}/52".format(
            sum(1 for r in completed if r["candidate"]["runner_identity"] == "byte_identical")
        ),
        "distinct_reference_relations": declared["distinct_reference_relations"],
        "distinct_comparisons_declared": declared["distinct_comparisons"],
        "distinct_comparisons_observed": len(observed_comparisons) or None,
        "enforcement_discriminating_receipts": declared[
            "enforcement_discriminating_receipts"
        ],
        "substantive_distinct_comparisons_declared": declared[
            "substantive_distinct_comparisons"
        ],
        "substantive_distinct_comparisons_observed": len(observed_substantive) or None,
        "density_reporting": "declared -> observed (memo v2.3 clause C)",
    }
    return {
        "schema": SUMMARY_SCHEMA,
        "run_id": run_id,
        # §10.2's declared wording for any non-complete run.  `stop_class`
        # preserves *why* it stopped without inventing a new status value:
        # a mismatch verdict, a protocol refusal, or a harness error (clause C).
        "status": status if complete else "incomplete_failed",
        "stop_class": None if complete else _stop_class(status, failure),
        "package_pass": bool(complete and all(r["status"] == "pass" for r in completed)),
        "headline": headline,
        "denominators": dict(declared),
        "excluded_modes": [
            {"pattern": pattern, "reason": reason}
            for pattern, reason in EXCLUDED_MODE_PATTERNS
        ],
        "execution_order": [r["cell_id"] for r in receipts],
        "measurement_protocol": "not_applicable/correctness_only",
        "warmup": 0,
        "measured": 0,
        "timing_recorded": False,
        "observed_comparisons": sorted(observed_comparisons),
        "selection_identity_note": (
            "selection_identity_same is a per-run observation, not a package property; "
            "it must not be improved by re-running, and the package does not claim to "
            "verify the plans selected in the frozen campaigns (memo v2.3 clauses B/D)"
        ),
        "selection_classification_digest": identity.get("selection_classification_digest"),
        "identity": {
            "source_digest": identity["source"]["source_digest"],
            "source_file_list_digest": identity["source"]["source_file_list_digest"],
            "source_file_list": identity["source"]["source_file_list"],
            "harness_digest": identity["harness"]["harness_digest"],
            "harness_modules": identity["harness"]["harness_modules"],
            "spec_digest": identity["spec_digest"],
            "predeclared_digest": identity["predeclared_digest"],
            "selection_classification_digest": identity.get(
                "selection_classification_digest"
            ),
            "selection_classification_path": identity.get(
                "selection_classification_path"
            ),
            "policy_manifest_digest": identity.get("policy_manifest_digest"),
            "git": identity["git"],
            # Clause A/B — three databases, three data states, three fingerprints.
            "database_topology": identity.get("database_topology"),
            "database_by_family": identity.get("database_by_family"),
            "dataset_fingerprint_by_family": identity.get("dataset_fingerprint_by_family"),
            "dataset_fingerprint_recheck": identity.get("dataset_fingerprint_recheck"),
            "statistics_digest_by_family": identity.get("statistics_digest_by_family"),
            "implementation_fidelity_audit": identity["implementation_fidelity_audit"],
        },
        "four_layer_declaration": four_layer_declaration(
            identity,
            selection_same=sum(
                1 for r in completed if r["candidate"]["selection_identity"] == "same"
            ),
            runner_byte_identical=sum(
                1
                for r in completed
                if r["candidate"]["runner_identity"] == "byte_identical"
            ),
        ),
        "failure": failure,
        "forbidden_language_reminder": (
            "38 must never be separated from '15 substantive distinct comparisons'; "
            "'38 independent receipts/comparisons' is forbidden (memo 12.5)"
        ),
    }


def _write_summary_csv(run_dir: Path, receipts: Sequence[Mapping[str, Any]]) -> None:
    import csv

    columns = [
        "cell_id", "short_id", "family", "shape_class", "status", "failure_reason",
        "boundary_kind", "candidate_fidelity", "selection_identity", "runner_identity",
        "candidate_row_count", "reference_row_count", "candidate_digest",
        "reference_digest", "actual_only_rows", "reference_only_rows", "vacuous",
        "discriminating_power", "reference_relation_id", "comparison_id",
        "observed_comparison_id", "selection_difference_cause", "selection_stability",
        "crossvalidated", "crossvalidation_digest_equal", "policy_cardinality_observed",
        "ordered_sequence_match",
    ]
    with (run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for receipt in receipts:
            result = receipt.get("result", {})
            candidate = receipt.get("candidate", {})
            derived = receipt.get("derived", {})
            writer.writerow(
                {
                    "cell_id": receipt["cell_id"],
                    "short_id": receipt["short_id"],
                    "family": receipt["family"],
                    "shape_class": receipt["shape_class"],
                    "status": receipt.get("status"),
                    "failure_reason": receipt.get("failure_reason"),
                    "boundary_kind": receipt.get("boundary", {}).get("kind"),
                    "candidate_fidelity": candidate.get("candidate_fidelity"),
                    "selection_identity": candidate.get("selection_identity"),
                    "runner_identity": candidate.get("runner_identity"),
                    "candidate_row_count": result.get("candidate_row_count"),
                    "reference_row_count": result.get("reference_row_count"),
                    "candidate_digest": result.get("candidate_digest"),
                    "reference_digest": result.get("reference_digest"),
                    "actual_only_rows": result.get("actual_only_rows"),
                    "reference_only_rows": result.get("reference_only_rows"),
                    "vacuous": result.get("vacuous"),
                    "discriminating_power": result.get("discriminating_power"),
                    "reference_relation_id": result.get("reference_relation_id"),
                    "comparison_id": result.get("comparison_id"),
                    "observed_comparison_id": result.get("observed_comparison_id"),
                    "selection_difference_cause": candidate.get(
                        "selection_difference_cause"
                    ),
                    "selection_stability": candidate.get("selection_stability"),
                    "crossvalidated": result.get("crossvalidated"),
                    "crossvalidation_digest_equal": result.get("crossvalidation_digest_equal"),
                    "policy_cardinality_observed": derived.get("policy_cardinality_observed"),
                    "ordered_sequence_match": result.get("ordered_sequence_match"),
                }
            )
