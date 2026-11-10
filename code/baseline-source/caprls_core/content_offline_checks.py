"""Static and offline verification of content-boundary cases."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

import yaml

from caprls_core.content_falsifier import lift_named_cte, run_offline, sha256_plain

FORBIDDEN_CLOSURE_RE = re.compile(
    r"^(planner($|\.)|caprls_core\.result_schema$|caprls_core\.e\d+[a-z]?_)"
)

#: §1.3 / §5.5 — the frozen context bindings, stated in the memo and reproduced
#: from the frozen E10 runner SQL.  Used **only** for the offline predicate
#: reconciliation below; the run itself always reads the live context row.
FROZEN_CONTEXT_BINDINGS = {
    "user_id": 90,
    "tenant_id": 90,
    "region": "region_2",
    "purpose": "purpose_2",
    "clearance": 2,
}


# ---------------------------------------------------------------------------
# 1. Static import-closure test (§5.2 mechanism 3)
# ---------------------------------------------------------------------------
def _module_path(root: Path, module: str) -> Optional[Path]:
    candidate = Path(root) / (module.replace(".", "/") + ".py")
    if candidate.is_file():
        return candidate
    package = Path(root) / module.replace(".", "/") / "__init__.py"
    if package.is_file():
        return package
    return None


def _imports_of(path: Path, module: str) -> Set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    package = module.rsplit(".", 1)[0] if "." in module else module
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package
                target = "{}.{}".format(base, node.module) if node.module else base
            else:
                target = node.module or ""
            if target:
                found.add(target)
                for alias in node.names:
                    found.add("{}.{}".format(target, alias.name))
    return found


def static_import_closure(root: Path, entry: str) -> Dict[str, Any]:
    """AST transitive closure of an entry module, restricted to first-party code.

    Retained **only as a CI regression guard**.  It is explicitly *not* the
    independence proof: a direct-import check passes while the entire planner
    sits in the process (§5.2).  The proof is process isolation plus the
    in-child ``sys.modules`` assertion.
    """

    root = Path(root)
    seen: Set[str] = set()
    queue = [entry]
    while queue:
        module = queue.pop()
        if module in seen:
            continue
        path = _module_path(root, module)
        if path is None:
            continue
        seen.add(module)
        for target in _imports_of(path, module):
            if target.split(".")[0] not in {"caprls_core", "planner"}:
                continue
            if target in seen:
                continue
            if _module_path(root, target) is not None:
                queue.append(target)
            elif "." in target:
                parent = target.rsplit(".", 1)[0]
                if _module_path(root, parent) is not None:
                    queue.append(parent)
    closure = sorted(seen - {entry})
    offenders = [name for name in closure if FORBIDDEN_CLOSURE_RE.match(name)]
    return {
        "entry": entry,
        "closure": closure,
        "forbidden": offenders,
        "status": "pass" if not offenders else "fail",
        "role": "ci_regression_guard_not_the_independence_proof",
    }


# ---------------------------------------------------------------------------
# 2. Subprocess sys.modules assertion, dry (no database)
# ---------------------------------------------------------------------------
def subprocess_isolation_dry_run(root: Path) -> Dict[str, Any]:
    """Run the child's widened assertion for real, without touching a database."""

    proc = subprocess.run(
        [sys.executable, "-m", "caprls_core.content_reference", "--assert-isolation-only"],
        cwd=str(root), text=True, capture_output=True,
    )
    if proc.returncode != 0:
        return {"status": "fail", "detail": proc.stderr[-2000:]}
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    first_party = [
        name
        for name in payload["resident_modules"]
        if name.split(".")[0] in {"caprls_core", "planner"}
    ]
    offenders = [
        name for name in payload["resident_modules"]
        if re.match(payload["assertion_pattern"], name)
    ]
    return {
        "status": "pass" if payload.get("status") == "isolated" and not offenders else "fail",
        "assertion_pattern": payload["assertion_pattern"],
        "resident_module_count": payload["resident_module_count"],
        "first_party_resident_modules": first_party,
        "forbidden": offenders,
    }


# ---------------------------------------------------------------------------
# 3. Spec <-> frozen-record transcription reconciliation
# ---------------------------------------------------------------------------
def transcription_reconciliation(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Read-only reconciliation of the spec against the frozen authorities."""

    root = Path(root)
    import csv

    rows = list(
        csv.DictReader(
            (root / "results/summarized/SIGMOD_CURRENT/correctness_cells.csv").open(
                encoding="utf-8"
            )
        )
    )
    frozen_ids = {row["cell_id"] for row in rows}
    spec_ids = {cell["cell_id"] for cell in spec["cells"]}
    checks: Dict[str, Any] = {
        "cell_identity_rows": len(rows),
        "cell_ids_match_correctness_cells_csv": frozen_ids == spec_ids,
        "spec_cells": len(spec["cells"]),
    }
    frozen_templates = {}
    for row in rows:
        frozen_templates[row["cell_id"]] = row["template_ids"]
    mismatched_templates = [
        cell["short_id"]
        for cell in spec["cells"]
        if frozen_templates.get(cell["cell_id"]) != cell["frozen"]["selected_template_id"]
    ]
    checks["selected_template_ids_match_summary_csv"] = not mismatched_templates
    checks["selected_template_mismatches"] = mismatched_templates

    stale = root / "results/raw/E10_PROTOCOL"
    checks["stale_e10_campaign_not_referenced"] = not any(
        "E10_PROTOCOL" in cell["frozen"]["record"] for cell in spec["cells"]
    )
    checks["stale_e10_campaign_exists_on_disk"] = stale.exists()
    checks["status"] = (
        "pass"
        if (
            checks["cell_ids_match_correctness_cells_csv"]
            and checks["selected_template_ids_match_summary_csv"]
            and checks["stale_e10_campaign_not_referenced"]
            and checks["spec_cells"] == 52
        )
        else "fail"
    )
    return checks


# ---------------------------------------------------------------------------
# 4. Offline predicate reconciliation against the frozen E10 runner SQL
# ---------------------------------------------------------------------------
def frozen_predicate_reconciliation(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Render the reference predicate offline and look for it in the frozen SQL.

    Applies to the 7 E10 cells whose frozen runner SQL carries the policy or
    guard predicate inline.  It does **not** apply to E2: §5.4/V2-N5 established
    that the frozen E2 record contains no predicate at all, so no reconciliation
    against the predicate that actually built the frozen matview is possible —
    only against a live re-render, which is the run's job.  Q2/Q7 read the MAV
    and Q3/Q9 carry artifact scope only, so their frozen text carries no
    predicate either.
    """

    from caprls_core import content_reference

    root = Path(root)
    policies = content_reference.load_policy_manifest(root)
    results: List[Dict[str, Any]] = []
    for cell in spec["cells"]:
        if cell["family"] != "E10":
            continue
        record_path = root / cell["frozen"]["record"]
        with record_path.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        runner_sql = record["sql"]["runner_sql"]
        payload = content_reference.build_reference(
            cell, policies, FROZEN_CONTEXT_BINDINGS
        )
        predicate = payload["reference_predicate_text"]
        # The frozen text writes the exact predicate inside a parenthesised
        # conjunct; compare on whitespace-normalised containment.
        normalized_sql = " ".join(runner_sql.split())
        normalized_predicate = " ".join(predicate.split())
        applicable = normalized_predicate in normalized_sql
        results.append(
            {
                "short_id": cell["short_id"],
                "predicate_present_in_frozen_runner_sql": applicable,
                "predicate_source": cell["boundary"]["predicate"]["source"],
            }
        )
    reconcilable = [r for r in results if r["predicate_present_in_frozen_runner_sql"]]
    return {
        "cells_examined": len(results),
        "cells_reconciled_against_frozen_text": len(reconcilable),
        "reconciled": sorted(r["short_id"] for r in reconcilable),
        "not_reconcilable": sorted(
            r["short_id"] for r in results if not r["predicate_present_in_frozen_runner_sql"]
        ),
        "note": "E2 is excluded by construction: the frozen E2 record contains no "
        "predicate. Q2/Q7 read the MAV and Q3/Q9 "
        "carry artifact scope only, so their frozen text carries no predicate.",
        "status": "pass" if len(reconcilable) >= 7 else "fail",
    }


# ---------------------------------------------------------------------------
# 5. Reference generation for all 52 cells (E2/E10 with the frozen bindings)
# ---------------------------------------------------------------------------
def reference_generation_dry_run(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Build every reference boundary SQL offline and run the structural guard."""

    from caprls_core import content_reference

    policies = content_reference.load_policy_manifest(Path(root))
    built: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []
    for cell in spec["cells"]:
        context = None if cell["family"] == "E3" else FROZEN_CONTEXT_BINDINGS
        try:
            payload = content_reference.build_reference(cell, policies, context)
        except Exception as exc:  # noqa: BLE001 - report, do not raise
            failures.append({"short_id": cell["short_id"], "error": str(exc)})
            continue
        built.append(
            {
                "short_id": cell["short_id"],
                "reference_authority": payload["reference_authority"],
                "boundary_sql_digest": payload["boundary_sql_digest"],
                "reference_relation_id": cell["reference"]["reference_relation_id"],
            }
        )
    distinct_sql = len({item["boundary_sql_digest"] for item in built})
    distinct_relations = len({item["reference_relation_id"] for item in built})
    return {
        "cells_built": len(built),
        "failures": failures,
        "distinct_reference_sql_texts": distinct_sql,
        "distinct_reference_relation_ids": distinct_relations,
        "status": "pass" if len(built) == 52 and not failures else "fail",
        "note": "E2/E10 use the frozen context bindings offline; the run always "
        "reads the live context row from public.synthetic_context",
    }


# ---------------------------------------------------------------------------
# 6. Candidate boundary extraction, offline, from the frozen runner SQL
# ---------------------------------------------------------------------------
def candidate_extraction_dry_run(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Exercise the three extraction paths against the frozen texts."""

    from caprls_core.content_verify import extract_candidate_boundary

    root = Path(root)
    per_fidelity: Dict[str, int] = {}
    failures: List[Dict[str, str]] = []
    extracted: List[Dict[str, Any]] = []
    for cell in spec["cells"]:
        record_path = root / cell["frozen"]["record"]
        with record_path.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        runner_sql = (
            record["sql"]["text"] if cell["family"] == "E3" else record["sql"]["runner_sql"]
        )
        try:
            boundary_sql, proof, rewrite = extract_candidate_boundary(cell, runner_sql)
        except Exception as exc:  # noqa: BLE001 - report, do not raise
            failures.append({"short_id": cell["short_id"], "error": str(exc)})
            continue
        fidelity = cell["candidate"]["candidate_fidelity"]
        per_fidelity[fidelity] = per_fidelity.get(fidelity, 0) + 1
        extracted.append(
            {
                "short_id": cell["short_id"],
                "fidelity": fidelity,
                "boundary_sql_digest": sha256_plain(boundary_sql),
                "rewrite_touches": (rewrite or {}).get("touches"),
            }
        )
    return {
        "cells_extracted": len(extracted),
        "per_fidelity": per_fidelity,
        "failures": failures,
        "status": "pass"
        if len(extracted) == 52
        and per_fidelity
        == {
            "verbatim_subplan_planner_anchored": 33,
            "verbatim_subplan_text_anchored": 5,
            "re_rendered_projection": 14,
        }
        else "fail",
        "note": "extraction is exercised here against the FROZEN runner SQL; the run "
        "extracts from the HEAD-selected runner SQL",
    }


# ---------------------------------------------------------------------------
# 7. Transaction-script construction for all 52 cells
# ---------------------------------------------------------------------------
def transaction_script_dry_run(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the §8.1 script for every cell and check its structural invariants."""

    from caprls_core import content_reference
    from caprls_core.content_psql import validate_statement_head
    from caprls_core.content_verify import (
        PINNED_GUCS,
        build_transaction_script,
        extract_candidate_boundary,
    )

    root = Path(root)
    policies = content_reference.load_policy_manifest(root)
    built = 0
    failures: List[Dict[str, str]] = []
    for cell in spec["cells"]:
        record_path = root / cell["frozen"]["record"]
        with record_path.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        runner_sql = (
            record["sql"]["text"] if cell["family"] == "E3" else record["sql"]["runner_sql"]
        )
        context = None if cell["family"] == "E3" else FROZEN_CONTEXT_BINDINGS
        try:
            candidate_sql, _proof, _rewrite = extract_candidate_boundary(cell, runner_sql)
            payload = content_reference.build_reference(cell, policies, context)
            companion = content_reference.policy_cardinality_sql(
                cell, payload["reference_predicate_text"]
            )
            script = build_transaction_script(
                cell, candidate_sql, payload["boundary_sql"], companion,
                crossvalidate=bool(cell["crossvalidate"]),
            )
            validate_statement_head(script)
            for required in (
                "BEGIN ISOLATION LEVEL REPEATABLE READ;",
                "CREATE TEMP TABLE caprls_content_actual ON COMMIT DROP AS",
                "CREATE TEMP TABLE caprls_content_reference ON COMMIT DROP AS",
                "assert_rls_bypass",
                "assert_deterministic_collations",
                "pg_current_snapshot()",
                "COMMIT;",
                # F1 regression guard: search_path must be emitted in identifier
                # form, never through quote_literal.
                "SET LOCAL search_path TO pg_catalog, public;",
                # F2 regression guard: the GUC read-back must be case-insensitive.
                "jsonb_object_agg(lower(name), setting)",
                "WHERE lower(name) IN (",
            ):
                if required not in script:
                    raise AssertionError("missing {!r}".format(required))
            if "SET LOCAL search_path = '" in script:
                raise AssertionError("search_path emitted through quote_literal (F1)")
            if script.count("SET LOCAL ") != len(PINNED_GUCS):
                raise AssertionError(
                    "expected {} SET LOCAL statements".format(len(PINNED_GUCS))
                )
            for banned in ("EXPLAIN", "ANALYZE", "INSERT ", "UPDATE ", "DELETE ", "DROP "):
                if banned in script.upper().replace("ON COMMIT DROP", ""):
                    raise AssertionError("script contains {!r}".format(banned))
            built += 1
        except Exception as exc:  # noqa: BLE001 - report, do not raise
            failures.append({"short_id": cell["short_id"], "error": str(exc)})
    return {
        "scripts_built": built,
        "failures": failures,
        "pinned_gucs": len(PINNED_GUCS),
        "status": "pass" if built == 52 and not failures else "fail",
    }


# ---------------------------------------------------------------------------
# 7b. LIVE pinned-GUC check — mandatory precondition from the F1/F2 attribution
# ---------------------------------------------------------------------------
def live_pinned_guc_check(pg_env: Optional[Any]) -> Dict[str, Any]:
    """Issue the 16 `SET LOCAL`s against a real server, read them back, and
    resolve an unqualified relation.

    F1 and F2 both survived a 10/10 offline pass because
    ``transaction_script_dry_run`` inspects the script's *text* and never
    executes it: `SET LOCAL search_path = 'pg_catalog, public'` is perfectly
    well-formed text that installs one schema literally named
    ``pg_catalog, public``, and a case-sensitive `pg_settings` read-back is
    equally well-formed. **A gate that passes while the first cell of every
    family is guaranteed to fail is not a gate.**

    When no database is configured this returns
    ``status: skipped_requires_database`` — never ``pass``.  The suite's overall
    status degrades to ``pass_offline_only`` so a skipped live check can never
    read as green.
    """

    from caprls_core.content_verify import PINNED_GUCS, render_pinned_guc

    if pg_env is None:
        return {
            "status": "skipped_requires_database",
            "reason": "no --pg-host/--pg-user/--pg-database supplied to offline-checks",
            "consequence": "F1/F2-class defects cannot be excluded by this run of the gate",
            "pinned_gucs": len(PINNED_GUCS),
        }

    from caprls_core.content_psql import ContentPsqlError, run_script

    guc_lines = "\n".join(render_pinned_guc(n, v) for n, v in PINNED_GUCS)
    names = ", ".join(
        "'" + n.lower().replace("'", "''") + "'" for n, _ in PINNED_GUCS
    )
    probe_relations = (
        "share_acl", "group_membership", "purpose_policy", "document",
        "tpch_customer", "job_title",
    )
    probe_list = ", ".join("'" + r + "'" for r in probe_relations)
    script = "\n".join(
        [
            "BEGIN ISOLATION LEVEL REPEATABLE READ;",
            guc_lines,
            "SELECT '@@GUCCHECK:search_path:' || current_setting('search_path');",
            "SELECT '@@GUCCHECK:current_schemas:' || array_to_json(current_schemas(false))::text;",
            "SELECT '@@GUCCHECK:settings:' || (SELECT jsonb_object_agg(lower(name), setting)::text "
            "FROM pg_settings WHERE lower(name) IN ({}));".format(names),
            "SELECT '@@GUCCHECK:probe_relation:' || COALESCE((SELECT c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
            "AND c.relkind IN ('r','m','v') AND c.relname IN ({}) "
            "ORDER BY c.relname LIMIT 1), '');".format(probe_list),
            "COMMIT;",
        ]
    ) + "\n"
    try:
        raw = run_script(script, pg_env)
    except ContentPsqlError as exc:
        return {"status": "fail", "stage": "set_local", "error": str(exc)[-2000:]}

    values: Dict[str, str] = {}
    for line in raw.splitlines():
        if line.startswith("@@GUCCHECK:"):
            name, _, rest = line[len("@@GUCCHECK:"):].partition(":")
            values[name] = rest

    result: Dict[str, Any] = {"database": getattr(pg_env, "database", None)}
    failures: List[str] = []

    search_path = values.get("search_path", "")
    result["search_path"] = search_path
    # The F1 signature: a single quoted schema literally named "pg_catalog, public".
    if '"' in search_path:
        failures.append("search_path_is_a_single_quoted_identifier (F1 signature)")
    schemas = json.loads(values.get("current_schemas", "[]") or "[]")
    result["current_schemas"] = schemas
    if "public" not in schemas:
        failures.append("public_not_on_search_path (F1)")
    if "pg_catalog" not in schemas:
        failures.append("pg_catalog_not_on_search_path")

    settings = json.loads(values.get("settings", "null") or "null") or {}
    result["settings_read_back"] = len(settings)
    result["settings"] = settings
    missing = sorted({n.lower() for n, _ in PINNED_GUCS} - set(settings))
    if missing:
        failures.append("guc_read_back_missing:{} (F2)".format(",".join(missing)))
    if str(settings.get("client_encoding", "")).upper() != "UTF8":
        failures.append("client_encoding_is_not_UTF8")

    probe = values.get("probe_relation", "").strip()
    result["probe_relation"] = probe or None
    if probe:
        try:
            unqualified = run_script(
                "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
                + guc_lines
                + "\nSELECT '@@GUCCHECK:unqualified:' || (SELECT count(*) FROM {})::text;"
                "\nCOMMIT;\n".format(probe),
                pg_env,
            )
            result["unqualified_resolution"] = "ok" if "@@GUCCHECK:unqualified:" in unqualified else "no_output"
            if "@@GUCCHECK:unqualified:" not in unqualified:
                failures.append("unqualified_relation_did_not_resolve (F1)")
        except ContentPsqlError as exc:
            result["unqualified_resolution"] = "failed"
            result["unqualified_error"] = str(exc)[-1000:]
            failures.append("unqualified_relation_did_not_resolve (F1)")
    else:
        result["unqualified_resolution"] = "no_probe_relation_present"
        result["unqualified_note"] = (
            "no public relation from the probe list exists in this database; "
            "search_path membership was still proved by current_schemas(false)"
        )

    result["failures"] = failures
    result["status"] = "pass" if not failures else "fail"
    return result


# ---------------------------------------------------------------------------
# 7c. Live end-to-end transaction-script check
# ---------------------------------------------------------------------------
#: A trivial two-row boundary that compares nothing.  The text column carries an
#: embedded newline **on purpose**: the parser's core invariant is that a tagged
#: value never spans lines because ``jsonb::text`` escapes control characters,
#: and this probe proves that invariant against a live server rather than
#: assuming it.
_PROBE_BOUNDARY_SQL = (
    "SELECT s AS probe_id, ('alpha' || chr(10) || 'beta')::text AS probe_text, "
    "s AS __rid FROM generate_series(1, 2) AS s"
)
_PROBE_CARDINALITY_SQL = "SELECT count(*) FROM generate_series(1, 2) AS s"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def live_transaction_script_check(pg_env: Optional[Any]) -> Dict[str, Any]:
    """Content-boundary verification helper."""

    if pg_env is None:
        return {
            "status": "skipped_requires_database",
            "reason": "no --pg-host/--pg-user/--pg-database supplied to offline-checks",
            "consequence": "Tag-parsing defects cannot be excluded without a database check",
        }

    from caprls_core.content_psql import ContentPsqlError, run_script
    from caprls_core.content_verify import (
        PINNED_GUCS,
        build_transaction_script,
        parse_tagged_output,
    )
    from caprls_core.e3_sigmod_preview import canonical_result_from_row_texts

    probe_cell = {
        "cell_id": "GATE_PROBE",
        "short_id": "GATE_PROBE",
        "family": "GATE",
        "boundary": {
            "kind": "exact_authorized",
            "reference_relation": "public.caprls_gate_probe_absent_relation",
            "reference_alias": "s",
            "rid_col": "__rid",
            "columns": [],
            "refinement": {},
        },
        "crossvalidate": True,
    }
    script = build_transaction_script(
        probe_cell, _PROBE_BOUNDARY_SQL, _PROBE_BOUNDARY_SQL,
        _PROBE_CARDINALITY_SQL, crossvalidate=True,
    )
    try:
        raw = run_script(script, pg_env)
    except ContentPsqlError as exc:
        return {"status": "fail", "stage": "execute", "error": str(exc)[-2000:]}
    try:
        tagged = parse_tagged_output(raw)
    except Exception as exc:  # noqa: BLE001 - the parser is what is under test
        return {
            "status": "fail",
            "stage": "parse",
            "error": "{}: {}".format(type(exc).__name__, exc),
            "raw_tail": raw[-1500:],
        }

    failures: List[str] = []
    observed: Dict[str, Any] = {}

    def _require(name: str) -> str:
        if name not in tagged:
            failures.append("missing tag: " + name)
            return ""
        return tagged[name]

    def _as_int(name: str) -> Optional[int]:
        value = _require(name)
        try:
            return int(value)
        except (TypeError, ValueError):
            failures.append("tag {} is not an integer: {!r}".format(name, value))
            return None

    def _as_json(name: str) -> Any:
        value = _require(name)
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            failures.append("tag {} is not JSON: {!r}".format(name, value[:120]))
            return None

    for name in ("assert_rls_bypass", "assert_deterministic_collations"):
        if _require(name).strip() != "1":
            failures.append("{} did not evaluate to 1".format(name))

    snapshot = _as_json("snapshot") or {}
    observed["isolation"] = snapshot.get("isolation")
    if snapshot.get("isolation") != "repeatable read":
        failures.append("snapshot.isolation is not 'repeatable read'")
    for key in ("snapshot_token", "current_user", "pg_version"):
        if not snapshot.get(key):
            failures.append("snapshot.{} missing".format(key))

    gucs = _as_json("gucs") or {}
    observed["gucs_read_back"] = len(gucs)
    if len(gucs) != len(PINNED_GUCS):
        failures.append(
            "gucs read back {} of {}".format(len(gucs), len(PINNED_GUCS))
        )
    if str(gucs.get("client_encoding", "")).upper() != "UTF8":
        failures.append("client_encoding is not UTF8")
    if any(key != key.lower() for key in gucs):
        failures.append("guc keys are not lowercased")

    role = _as_json("role") or {}
    if not isinstance(role.get("rolsuper"), bool) or not isinstance(
        role.get("rolbypassrls"), bool
    ):
        failures.append("role block is not typed")

    pre = _as_int("policy_state_pre")
    post = _as_int("policy_state_post")
    observed["policy_state"] = [pre, post]
    if pre is None or post is None or pre != post:
        failures.append("policy_state_pre/post are not equal integers")

    columns = _as_json("columns")
    observed["column_rows"] = len(columns) if isinstance(columns, list) else None
    if not isinstance(columns, list) or len(columns) != 6:
        failures.append("columns is not a 6-entry list (3 columns x 2 temp tables)")
    elif any(
        set(c) != {"table", "ordinal", "name", "data_type", "is_nullable"}
        for c in columns
    ):
        failures.append("columns entries have the wrong shape")

    counts = _as_json("row_counts") or {}
    observed["row_counts"] = counts
    if counts.get("candidate_row_count") != 2 or counts.get("reference_row_count") != 2:
        failures.append("row_counts are not 2 / 2")

    cardinality = _as_int("policy_cardinality")
    observed["policy_cardinality"] = cardinality
    if cardinality != 2:
        failures.append("policy_cardinality is not 2")

    candidate_digest = _require("candidate_digest").strip()
    reference_digest = _require("reference_digest").strip()
    observed["digest_shape_ok"] = bool(
        _SHA256_RE.fullmatch(candidate_digest) and _SHA256_RE.fullmatch(reference_digest)
    )
    if not observed["digest_shape_ok"]:
        failures.append("digests are not 'sha256:<64 hex>'")
    if candidate_digest != reference_digest:
        failures.append("identical relations produced different digests")

    bag = _as_json("bag_difference") or {}
    observed["bag_difference"] = {
        k: bag.get(k) for k in ("actual_only_rows", "reference_only_rows")
    }
    if bag.get("actual_only_rows") != 0 or bag.get("reference_only_rows") != 0:
        failures.append("identical relations produced a non-zero bag difference")
    for key in ("actual_only_witnesses", "reference_only_witnesses"):
        if not isinstance(bag.get(key), list):
            failures.append("bag_difference.{} is not a list".format(key))

    from caprls_core.content_verify import parse_bool_text

    ordered = _require("ordered_sequence_match").strip()
    observed["ordered_sequence_match_raw"] = ordered
    try:
        observed["ordered_sequence_match"] = parse_bool_text(
            ordered, "ordered_sequence_match"
        )
    except Exception as exc:  # noqa: BLE001 - the parser is what is under test
        failures.append("ordered_sequence_match is not a boolean: {}".format(exc))

    rows_actual = _as_json("rows_actual")
    rows_reference = _as_json("rows_reference")
    observed["rows_transferred"] = [
        len(rows_actual) if isinstance(rows_actual, list) else None,
        len(rows_reference) if isinstance(rows_reference, list) else None,
    ]
    if not isinstance(rows_actual, list) or len(rows_actual) != 2:
        failures.append("rows_actual is not a 2-element list")
    if not isinstance(rows_reference, list) or len(rows_reference) != 2:
        failures.append("rows_reference is not a 2-element list")

    # The invariant the parser rests on: to_jsonb escapes control characters, so
    # a value containing a newline still arrives on ONE line.
    if isinstance(rows_actual, list) and rows_actual:
        sample = rows_actual[0]
        observed["probe_newline_escaped"] = ("\\n" in sample) and ("\n" not in sample)
        if not observed["probe_newline_escaped"]:
            failures.append(
                "to_jsonb did not escape the probe newline; the single-line "
                "invariant the parser relies on does not hold"
            )
        # §8.2 — the in-DB encoding must be byte-identical to the audited
        # Python primitive.
        python_digest = canonical_result_from_row_texts(tuple(rows_actual)).result_digest
        observed["python_digest_matches_in_db"] = python_digest == candidate_digest
        if not observed["python_digest_matches_in_db"]:
            failures.append(
                "in-database digest differs from canonical_result_from_row_texts"
            )

    noise = json.loads(tagged.get("__noise__", "[]"))
    observed["psql_command_tags_seen"] = len(noise)
    observed["psql_command_tags_sample"] = noise[:4]

    return {
        "status": "pass" if not failures else "fail",
        "database": getattr(pg_env, "database", None),
        "observed": observed,
        "failures": failures,
        "tags_parsed": sorted(k for k in tagged if k != "__noise__"),
        "note": "trivial two-row boundary, both sides identical; compares nothing",
    }


# ---------------------------------------------------------------------------
# 7d. Per-candidate cost-vector hook (v2.3 condition 3) — no database
# ---------------------------------------------------------------------------
def cost_vector_hook_check(root: Path) -> Dict[str, Any]:
    """Prove the E3 cost-vector observation hook is intact.

    v2.3 condition 3 requires the per-candidate prospective cost vector on every
    E3 receipt.  The vector is read by a pass-through wrapper around
    ``e3_main._verify_e3_static``, because ``e3_main.py`` is a frozen file and
    the cost map it builds is not reachable from ``_prepare_cell_live``'s return
    value.  If that function were renamed or its call site changed, the wrapper
    would simply never fire and all 33 E3 receipts would carry an **empty**
    vector — silently.  This check fails the gate instead.

    Verified without a database: the hook exists, the call site still calls it
    unqualified (so patching the module attribute is effective), the wrapper
    installs and restores, it records ``(template_id, Total Cost)``, it
    delegates unchanged, and an observation failure cannot perturb planning.
    """

    import inspect

    from caprls_core import e3_main as e3
    from caprls_core.content_verify import _E3CostVectorCapture

    checks: Dict[str, Any] = {}
    hook = getattr(e3, "_verify_e3_static", None)
    checks["hook_exists"] = callable(hook)
    if not checks["hook_exists"]:
        return {"status": "fail", "checks": checks, "reason": "_verify_e3_static is gone"}

    source = inspect.getsource(e3)
    # The call site must resolve the module global at call time for the wrapper
    # to be effective (i.e. an unqualified call, not `from ... import`-bound).
    checks["call_site_is_unqualified"] = "verification = _verify_e3_static(" in source
    checks["cost_is_computed_before_the_hook"] = (
        'costs[plan_id] = plan_root["Total Cost"]' in source
    )

    original = e3._verify_e3_static
    seen: List[Any] = []

    class _Sentinel:
        pass

    sentinel = _Sentinel()

    def _fake(template_id, runner_body, explain_json, *a, **k):
        seen.append((template_id, runner_body))
        return sentinel

    e3._verify_e3_static = _fake
    try:
        explain = [{"Plan": {"Total Cost": 1234.5}}]
        with _E3CostVectorCapture(e3) as capture:
            checks["wrapper_installed"] = e3._verify_e3_static is not _fake
            returned = e3._verify_e3_static("auth_index_enum_v1", "SELECT 1", explain)
            checks["delegates_unchanged"] = returned is sentinel
            checks["inner_called"] = len(seen) == 1
            # An unobservable EXPLAIN must not raise or perturb the delegate.
            e3._verify_e3_static("barrier_filter_v1", "SELECT 2", [{"Plan": {}}])
            checks["observation_failure_is_swallowed"] = len(seen) == 2
        checks["wrapper_restored"] = e3._verify_e3_static is _fake
        vector = capture.vector()
        checks["vector_records_cost"] = vector == [
            {
                "template_id": "auth_index_enum_v1",
                "prospective_total_cost": 1234.5,
                "runner_sql_digest": sha256_plain("SELECT 1"),
            }
        ]
    finally:
        e3._verify_e3_static = original

    checks["hook_restored_globally"] = e3._verify_e3_static is original
    failures = sorted(name for name, ok in checks.items() if ok is False)
    return {
        "status": "pass" if not failures else "fail",
        "checks": checks,
        "failures": failures,
        "note": "e3_main.py is byte-unmodified; the hook is a temporary, "
        "exception-proof, pass-through observer restored in finally",
    }


def selection_classification_check(root: Path, spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Exercise the classification table's runtime semantics (v2.3 clause A).

    The harness must classify **only** inside a declared admissible set, and
    refuse everywhere else.  Asserted here on the table as signed, so a table
    edit that widened the scope would fail the gate.
    """

    from caprls_core.content_verify import (
        classify_selection_difference,
        load_selection_classification,
    )

    path = Path(root) / "specs" / "selection_difference_classification.yaml"
    if not path.exists():
        return {"status": "fail", "reason": "classification table missing"}
    table = load_selection_classification(path)
    by_short = {c["short_id"]: c for c in spec["cells"]}
    results: Dict[str, str] = {}
    failures: List[str] = []

    def _probe(short: str, observed: str, expected: str) -> None:
        cell = by_short[short]
        got = classify_selection_difference(table, cell, observed)["selection_difference_cause"]
        results["{}<-{}".format(short, observed)] = got
        if got != expected:
            failures.append("{} observed {} -> {} (expected {})".format(
                short, observed, got, expected))

    _probe("E3_JOB_10a_group_acl_expensive", "barrier_filter_v1", "statistics")
    _probe("E3_JOB_10a_group_acl_expensive", "hybrid_intersect_v1", "unknown")
    _probe("E3_Q3_group_acl_expensive", "auth_index_enum_v1", "statistics")
    _probe("E3_Q5_group_acl_expensive", "barrier_filter_v1", "unknown")
    _probe("E3_Q3_cheap_tenant_sargable", "auth_index_enum_v1", "unknown")
    _probe("E10_Q3", "barrier_filter_v1", "unknown")
    listed = {e["short_id"] for e in table["entries"]}
    authorized = {
        c["short_id"] for c in spec["cells"]
        if c["family"] == "E3" and c["policy_id"] == "group_acl_expensive"
    }
    if listed != authorized:
        failures.append("scope drift: {}".format(sorted(listed ^ authorized)))
    return {
        "status": "pass" if not failures else "fail",
        "classified_cells": len(listed),
        "unlisted_cells": len(spec["cells"]) - len(listed),
        "probes": results,
        "failures": failures,
        "digest": sha256_plain(path.read_text(encoding="utf-8")),
    }


# ---------------------------------------------------------------------------
# 8. Receipt-schema invariants (§8.5 — no timing field at all)
# ---------------------------------------------------------------------------
def receipt_schema_invariants(root: Path) -> Dict[str, Any]:
    source = (Path(root) / "caprls_core" / "content_verify.py").read_text(encoding="utf-8")
    banned_fields = [
        '"duration_ms"', '"elapsed_ms"', '"execution_ms"', '"median_ms"',
        '"latency"', '"wall_ms"', "time.perf_counter", "time.monotonic",
    ]
    present = [token for token in banned_fields if token in source]
    return {
        "status": "pass" if not present else "fail",
        "banned_tokens_present": present,
        "note": "zero warmup / zero measured is enforced twice: the CLI rejects "
        "nonzero counts and the receipt schema has no timing field at all",
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run_all(
    root: Path,
    spec_path: Optional[Path] = None,
    pg_env: Optional[Any] = None,
) -> Dict[str, Any]:
    from caprls_core.content_spec_audit import run_audit

    root = Path(root)
    spec_path = Path(spec_path) if spec_path else root / "specs" / "content_cells.yaml"
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)

    checks: Dict[str, Any] = {}
    checks["live_pinned_guc_check"] = live_pinned_guc_check(pg_env)
    checks["live_transaction_script_check"] = live_transaction_script_check(pg_env)
    checks["cost_vector_hook_check"] = cost_vector_hook_check(root)
    checks["selection_classification_check"] = selection_classification_check(root, spec)
    checks["static_import_closure"] = static_import_closure(
        root, "caprls_core.content_reference"
    )
    checks["subprocess_isolation_dry_run"] = subprocess_isolation_dry_run(root)
    checks["implementation_fidelity_audit"] = run_audit(root, spec_path).to_dict()
    checks["offline_recomposition_falsifier"] = run_offline(root, spec_path)
    checks["transcription_reconciliation"] = transcription_reconciliation(root, spec)
    checks["frozen_predicate_reconciliation"] = frozen_predicate_reconciliation(root, spec)
    checks["reference_generation_dry_run"] = reference_generation_dry_run(root, spec)
    checks["candidate_extraction_dry_run"] = candidate_extraction_dry_run(root, spec)
    checks["transaction_script_dry_run"] = transaction_script_dry_run(root, spec)
    checks["receipt_schema_invariants"] = receipt_schema_invariants(root)

    def _status(value: Any) -> str:
        if isinstance(value, Mapping):
            if "status" in value:
                return str(value["status"])
            ok = all(v is not False for k, v in value.items() if isinstance(v, bool))
            return "pass" if ok else "fail"
        return "pass"

    statuses = {name: _status(value) for name, value in checks.items()}
    failed = sorted(name for name, s in statuses.items() if s == "fail")
    skipped = sorted(
        name for name, s in statuses.items() if s.startswith("skipped")
    )
    if failed:
        overall = "fail"
    elif skipped:
        # Never report a bare `pass` while a live-server check was skipped: the
        # whole point of the F1/F2 attribution is that a text-only gate went
        # 10/10 green while every family's first cell was guaranteed to fail.
        overall = "pass_offline_only"
    else:
        overall = "pass"
    return {
        "schema": "caprls-content-offline-checks-v2",
        "spec_digest": sha256_plain(Path(spec_path).read_text(encoding="utf-8")),
        "checks": checks,
        "statuses": statuses,
        "failed": failed,
        "skipped": skipped,
        "status": overall,
        "status_note": (
            "pass_offline_only means every offline check passed but a live-server "
            "check was skipped; it is NOT a green gate for a run"
        ),
    }
