"""Reference generation for content-boundary cases."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import yaml

from caprls_core.content_psql import (
    ContentPostgresEnv,
    ContentPsqlError,
    quote_literal,
    run_scalar,
    text_digest,
)
from caprls_core.manifest_validator import file_sha256

GENERATOR_ID = "content_reference_v1"

#: §5.2 mechanism 2 — widened forbidden pattern.  ``planner*`` alone is not
#: enough: ``caprls_core.result_schema`` is the single contaminating edge
#: (``result_schema.py:15 -> planner.core``) and ``caprls_core.e*_*`` pulls the
#: experiment drivers, which pull ``postgres_runner`` -> ``result_schema``.
FORBIDDEN_MODULE_RE = re.compile(
    r"^(planner($|\.)|caprls_core\.result_schema$|caprls_core\.e\d+[a-z]?_)"
)

#: §5.5 — the hard-coded execution timestamp shared by both sides.  Recorded as
#: part of ``context_binding_digest`` because nothing else pins it.
EXECUTION_TIMESTAMP = "2026-06-01 00:00:00+00"

_PARAM_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")

# ----------------------------------------------------------------- E3 transcription
CHEAP_TENANT_POLICY_ID = "cheap_tenant_sargable"
GROUP_ACL_POLICY_ID = "group_acl_expensive"
HYBRID_SELECTIVE_KEY_POLICY_ID = "hybrid_selective_key"

E3_PROTECTED_REL = {"tpch": "tpch_customer", "job": "job_title"}
E3_RID_COL = {"tpch": "c_custkey", "job": "t_id"}


class ContentReferenceError(RuntimeError):
    """Fail-closed error for the isolated generator."""


# --------------------------------------------------------------------------
# 1. Isolation assertion
# --------------------------------------------------------------------------
def resident_modules() -> List[str]:
    return sorted(sys.modules)


def assert_isolated() -> List[str]:
    """Refuse to emit anything if a forbidden module is resident.

    Returns the full sorted ``sys.modules`` list so the caller can record it —
    the receipt stores the list, not a bare ``"pass"`` (§5.2).
    """

    modules = resident_modules()
    offenders = [name for name in modules if FORBIDDEN_MODULE_RE.match(name)]
    if offenders:
        raise ContentReferenceError(
            "reference generator is contaminated; forbidden resident modules: "
            + ", ".join(offenders)
        )
    return modules


# --------------------------------------------------------------------------
# 2. Re-implemented predicate renderer (§5.4 option (c), T1 tripwire)
# --------------------------------------------------------------------------
def _sql_literal(value: Any, cast: Optional[str] = None) -> str:
    """Reference-side literal rendering.

    Deliberately re-implemented rather than imported: a bug in the shared
    renderer must not be invisible on both sides.  The observable contract is
    the *rendered text*, which the harness reconciles against a live call to
    the shared renderer (``predicate_text_reconciliation``).
    """

    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, str) and value.isdigit():
        rendered = value
    else:
        rendered = quote_literal(value)
    if cast:
        return rendered + "::" + cast
    return rendered


#: The two in-repo policy renderers disagree on timestamptz literal syntax:
#: ``oracle_audit._sql_literal`` emits ``'<ts>'::timestamptz`` (E2's candidate
#: path) while ``e10_study._render_policy_predicate`` emits
#: ``TIMESTAMPTZ '<ts>'`` (E10's).  The semantics are identical; only the
#: syntax differs.  The reference renders the *declared per-family form* so
#: that ``predicate_text_reconciliation`` compares like with like and a
#: ``differs`` verdict still means a real divergence.  The declared form is an
#: audited constant, so a change in either renderer is caught (§5.3, §5.5).
DEFAULT_TIMESTAMPTZ_FORM = "'{ts}'::timestamptz"


def context_bindings(
    context: Mapping[str, Any],
    relname: str,
    rid_col: str,
    timestamptz_form: Optional[str] = None,
) -> Dict[str, str]:
    """The full binding map, including the four E10-only keys.

    ``oracle_audit._render_exact_predicate``'s map (``oracle_audit.py:84-90``)
    lacks ``ctx_region``, ``ctx_purpose`` and ``ctx_clearance``, so
    ``purpose_region_invoice`` (E10 Q5) cannot be rendered by it today.  The
    bounded extension is declared in §5.5 and lives here.
    """

    form = timestamptz_form or DEFAULT_TIMESTAMPTZ_FORM
    values: Dict[str, str] = {
        "ctx_tenant_id": _sql_literal(context["tenant_id"]),
        "user_id": _sql_literal(context["user_id"]),
        "now": form.format(ts=EXECUTION_TIMESTAMP),
        "relname": _sql_literal(relname),
        "rid_domain_id": _sql_literal("{}.{}".format(relname, rid_col)),
    }
    for key, ctx_key in (
        ("ctx_region", "region"),
        ("ctx_purpose", "purpose"),
        ("ctx_clearance", "clearance"),
    ):
        if ctx_key in context:
            values[key] = _sql_literal(context[ctx_key])
    return values


def render_predicate(
    template: str,
    alias: str,
    rid_col: str,
    context: Mapping[str, Any],
    relname: str,
    timestamptz_form: Optional[str] = None,
) -> str:
    """Reference-side substitution.

    A *different implementation* from ``oracle_audit._render_exact_predicate``:
    that one does ``str.replace`` in descending key-length order; this one does
    a single regex pass with an exact-token callback, so a name-prefix collision
    cannot silently produce a different string on the two sides.  The two texts
    are reconciled by the harness and a divergence refuses the package.
    """

    if not isinstance(template, str) or not template.strip():
        raise ContentReferenceError("policy template is missing or empty")
    values = context_bindings(context, relname, rid_col, timestamptz_form)
    rendered = template.replace("{alias}", alias).replace("{rid_col}", rid_col)
    missing = sorted(set(_PARAM_RE.findall(rendered)) - set(values))
    if missing:
        raise ContentReferenceError(
            "cannot render policy predicate; missing runtime bindings: {}".format(missing)
        )

    def _sub(match: "re.Match[str]") -> str:
        return values[match.group(1)]

    resolved = _PARAM_RE.sub(_sub, rendered)
    if _PARAM_RE.search(resolved):
        raise ContentReferenceError("policy predicate still carries unbound parameters")
    if "{" in resolved or "}" in resolved:
        raise ContentReferenceError("policy predicate still carries unbound placeholders")
    return resolved


# --------------------------------------------------------------------------
# 3. E3 policy predicates — transcribed_from_implementation (§5.3)
# --------------------------------------------------------------------------
def e3_group_acl_predicate(workload: str, alias: Optional[str]) -> str:
    """Transcription of ``e3_main._group_acl_predicate`` (e3_main.py:3297-3308)."""

    protected_rel = E3_PROTECTED_REL[workload]
    rid_col = E3_RID_COL[workload]
    rid_ref = rid_col if alias is None else "{}.{}".format(alias, rid_col)
    return """EXISTS (
  SELECT 1
  FROM public.share_acl s
  JOIN public.group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'e3_user'
    AND s.relname = {}
    AND s.rid = {}
    AND s.permission = 'read'
)""".format(quote_literal("public." + protected_rel), rid_ref)


def e3_policy_predicate(workload: str, policy_id: str, alias: str) -> str:
    """Transcription of ``e3_main._policy_predicate`` (e3_main.py:3256-3274)."""

    if workload == "tpch":
        if policy_id == CHEAP_TENANT_POLICY_ID:
            return "{}.tenant_id = 1".format(alias)
        if policy_id == GROUP_ACL_POLICY_ID:
            return e3_group_acl_predicate(workload, alias)
        if policy_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return "{a}.tenant_id = 1 AND ({a}.c_custkey % 50) = 0".format(a=alias)
    if workload == "job":
        if policy_id == CHEAP_TENANT_POLICY_ID:
            return "{}.region_id = 1".format(alias)
        if policy_id == GROUP_ACL_POLICY_ID:
            return e3_group_acl_predicate(workload, alias)
        if policy_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return "{a}.region_id = 1 AND ({a}.t_id % 50) = 0".format(a=alias)
    raise ContentReferenceError(
        "unsupported E3 policy/workload pair: {}/{}".format(policy_id, workload)
    )


def e3_query_predicate(alias: str, key_name: str, key_value: str) -> str:
    """Transcription of ``e3_main._e3_query_predicate`` (e3_main.py:3985-3986)."""

    return "{}.{}::text = {}".format(alias, key_name, quote_literal(key_value))


E3_FULL_LOCAL_REFINEMENT_SOURCE = "original_query_sql_full_local_v1"


def e3_full_local_query_predicate(alias: str, query_id: str) -> str:
    """Return the protected-local predicate for a query."""
    if type(alias) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", alias) is None:
        raise ContentReferenceError("full-local refinement alias is malformed")
    predicates = {
        "Q3": "{a}.c_mktsegment = 'BUILDING'",
        "Q5": "{a}.c_mktsegment = 'BUILDING'",
        "Q7": "{a}.c_mktsegment = 'BUILDING'",
        "Q10": "{a}.c_mktsegment = 'BUILDING'",
        "Q12": "{a}.c_mktsegment = 'BUILDING'",
        "JOB_1a": "{a}.kind = 'movie' AND {a}.production_year BETWEEN 1990 AND 2010",
        "JOB_2a": "{a}.kind = 'movie' AND {a}.production_year BETWEEN 1985 AND 2015",
        "JOB_3c": "{a}.kind = 'movie' AND {a}.production_year BETWEEN 1980 AND 2005",
        "JOB_6d": "{a}.kind = 'movie' AND {a}.production_year >= 1995",
        "JOB_10a": "{a}.kind = 'movie' AND {a}.production_year BETWEEN 1990 AND 2020",
        "JOB_16b": "{a}.kind = 'movie' AND {a}.production_year >= 1980",
    }
    if query_id not in predicates:
        raise ContentReferenceError("unsupported original full-local query: " + str(query_id))
    return predicates[query_id].format(a=alias)


# --------------------------------------------------------------------------
# 4. Spec + manifest loading
# --------------------------------------------------------------------------
def load_spec(spec_path: Path) -> Mapping[str, Any]:
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != "caprls-content-cells-v1":
        raise ContentReferenceError("content cell spec has the wrong schema")
    cells = data.get("cells")
    if not isinstance(cells, list) or len(cells) != 52:
        raise ContentReferenceError("content cell spec must declare exactly 52 cells")
    return data


def find_cell(spec: Mapping[str, Any], cell_key: str) -> Mapping[str, Any]:
    for cell in spec["cells"]:
        if cell_key in (cell.get("cell_id"), cell.get("short_id")):
            return cell
    raise ContentReferenceError("unknown content cell: {}".format(cell_key))


def load_policy_manifest(root: Path) -> Mapping[str, Any]:
    path = Path(root) / "manifests" / "policies" / "synthetic_saas_policies.yaml"
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    policies = data.get("policies")
    if not isinstance(policies, Mapping):
        raise ContentReferenceError("policy manifest carries no policies block")
    return policies


def load_context(context_id: str, pg_env: ContentPostgresEnv) -> Mapping[str, Any]:
    """Read the bound context row.  §5.5: this row is a shared input."""

    payload = run_scalar(
        "SELECT canonical_context::text FROM public.synthetic_context WHERE context_id = {};".format(
            quote_literal(context_id)
        ),
        pg_env,
    )
    if not payload:
        raise ContentReferenceError("unknown synthetic context: {}".format(context_id))
    return json.loads(payload)


def context_binding_digest(context: Mapping[str, Any]) -> str:
    payload = {
        "context": {k: context[k] for k in sorted(context)},
        "execution_timestamp": EXECUTION_TIMESTAMP,
    }
    return text_digest(json.dumps(payload, sort_keys=True, separators=(",", ":")))


# --------------------------------------------------------------------------
# 5. Reference boundary SQL
# --------------------------------------------------------------------------
#: Constructs that sit **above** the enforcement boundary (§3.4) and therefore
#: may never appear in a reference statement at the top level.  A policy's own
#: correlated ``EXISTS (SELECT 1 FROM share_acl ... JOIN group_membership ...)``
#: is a join *inside* the enforcement predicate (§2.3) and is legitimate, so
#: every check below is depth-aware.
_STRUCTURAL_BANNED = (
    "limit",
    "offset",
    "distinct",
    "group",
    "order",
    "union",
    "intersect",
    "except",
    "unsafe_log",
    "with",
)


def _depth_zero_tokens(sql: str) -> List[str]:
    """Lowercase word tokens outside string literals and outside parentheses."""

    tokens: List[str] = []
    depth = 0
    index = 0
    length = len(sql)
    current: List[str] = []
    while index < length:
        char = sql[index]
        if char == "'":
            index += 1
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
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
        if depth == 0 and (char.isalnum() or char == "_"):
            current.append(char.lower())
        else:
            if current:
                tokens.append("".join(current))
                current = []
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


def structural_guard(sql: str, cell: Mapping[str, Any]) -> None:
    """Refuse a reference statement that reaches above the boundary (§3.4)."""

    if ";" in sql:
        raise ContentReferenceError("reference SQL must be a single statement")
    tokens = _depth_zero_tokens(sql)
    if not tokens or tokens[0] != "select":
        raise ContentReferenceError("reference SQL must be a single SELECT")
    for token in _STRUCTURAL_BANNED:
        if token in tokens:
            raise ContentReferenceError(
                "reference SQL for {} contains a banned top-level construct: {!r}".format(
                    cell.get("cell_id"), token
                )
            )
    if tokens.count("from") != 1:
        raise ContentReferenceError(
            "reference SQL for {} must read exactly one relation".format(cell.get("cell_id"))
        )
    if "join" in tokens:
        raise ContentReferenceError(
            "reference SQL for {} must not join above the boundary".format(cell.get("cell_id"))
        )
    reference_relation = cell["boundary"]["reference_relation"]
    if reference_relation.lower() not in " ".join(sql.lower().split()):
        raise ContentReferenceError(
            "reference SQL does not read the declared protected relation {}".format(
                reference_relation
            )
        )


def build_reference(
    cell: Mapping[str, Any],
    policies: Mapping[str, Any],
    context: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Return the reference boundary SQL plus its predicate provenance."""

    boundary = cell["boundary"]
    predicate_spec = boundary["predicate"]
    alias = boundary["reference_alias"]
    relation = boundary["reference_relation"]
    rid_col = boundary.get("reference_rid_col", boundary["rid_col"])
    source = predicate_spec["source"]

    timestamptz_form = predicate_spec.get("timestamptz_literal_form")

    if source == "e3_transcribed_from_implementation":
        workload = cell["workload"]
        predicate = e3_policy_predicate(workload, predicate_spec["e3_policy_config_id"], alias)
        authority = "transcribed_from_implementation"
    elif source == "manifest_exact_sql_template":
        policy = policies.get(predicate_spec["policy_manifest_key"])
        if not isinstance(policy, Mapping):
            raise ContentReferenceError(
                "policy manifest lacks {}".format(predicate_spec["policy_manifest_key"])
            )
        if context is None:
            raise ContentReferenceError("manifest-sourced predicates require a context row")
        predicate = render_predicate(
            str(policy["exact_sql_template"]),
            alias,
            rid_col,
            context,
            relation.split(".")[-1],
            timestamptz_form,
        )
        authority = "external_manifest"
    elif source == "e10_case_complete_guard_sql_template":
        # E10 Q5 only.  The compared object is the guard relation `cand`
        # (boundary_kind: guard_candidate_not_exact), so the reference must
        # generate the guard, not the exact-authorized stream (§3.3).
        if context is None:
            raise ContentReferenceError("guard rendering requires a context row")
        predicate = render_predicate(
            str(predicate_spec["guard_sql_template"]),
            alias,
            rid_col,
            context,
            relation.split(".")[-1],
            timestamptz_form,
        )
        authority = "external_manifest"
    else:
        raise ContentReferenceError("unknown predicate source: {}".format(source))

    refinement = boundary.get("refinement") or {}
    reference_r_c = refinement.get("reference_r_c")
    if refinement.get("source") == E3_FULL_LOCAL_REFINEMENT_SOURCE:
        if cell.get("family") != "E3":
            raise ContentReferenceError("original-query full-local refinement is E3-only")
        expected_reference = e3_full_local_query_predicate(alias, cell["query_id"])
        expected_candidate = e3_full_local_query_predicate("sel", cell["query_id"])
        if reference_r_c != expected_reference or refinement.get("r_c") != expected_candidate:
            raise ContentReferenceError("declared full-local refinement differs from original query transcription")
    conjuncts = ["(" + predicate + ")"]
    if reference_r_c:
        conjuncts.append("(" + reference_r_c + ")")
    sql = "SELECT {proj}\nFROM {rel} {alias}\nWHERE {where}".format(
        proj=boundary["reference_projection_sql"],
        rel=relation,
        alias=alias,
        where="\n  AND ".join(conjuncts),
    )
    structural_guard(sql, cell)
    return {
        "boundary_sql": sql,
        "boundary_sql_digest": text_digest(sql),
        "reference_predicate_text": predicate,
        "reference_predicate_digest": text_digest(predicate),
        "reference_authority": authority,
        "reference_r_c": reference_r_c,
        "generator": GENERATOR_ID,
    }


def policy_cardinality_sql(cell: Mapping[str, Any], predicate: str) -> str:
    """§9.2 companion query: ``SELECT count(*) FROM R WHERE Pi_c``."""

    boundary = cell["boundary"]
    return "SELECT count(*) FROM {rel} {alias} WHERE {pred}".format(
        rel=boundary["reference_relation"],
        alias=boundary["reference_alias"],
        pred=predicate,
    )


# --------------------------------------------------------------------------
# 6. CLI — one cell per invocation
# --------------------------------------------------------------------------
def _repo_root(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).resolve()
    return Path(__file__).resolve().parent.parent


def emit(
    *,
    cell_key: str,
    root: Path,
    spec_path: Path,
    needs_context: bool,
) -> Dict[str, Any]:
    modules = assert_isolated()
    spec = load_spec(spec_path)
    cell = find_cell(spec, cell_key)
    policies = load_policy_manifest(root)
    context: Optional[Mapping[str, Any]] = None
    context_digest: Optional[str] = None
    if needs_context:
        pg_env = ContentPostgresEnv.from_environment()
        context = load_context(cell["context_id"], pg_env)
        context_digest = context_binding_digest(context)
    payload = build_reference(cell, policies, context)
    payload.update(
        {
            "cell_id": cell["cell_id"],
            "short_id": cell["short_id"],
            "policy_cardinality_sql": policy_cardinality_sql(
                cell, payload["reference_predicate_text"]
            ),
            "context_binding_digest": context_digest,
            "context_id": cell["context_id"],
            "spec_digest": file_sha256(Path(spec_path)),
            "policy_manifest_digest": file_sha256(
                Path(root) / "manifests" / "policies" / "synthetic_saas_policies.yaml"
            ),
            "reference_generator_digest": file_sha256(Path(__file__)),
            "executor_digest": file_sha256(Path(__file__).with_name("content_psql.py")),
            "executor": "private_duplicated_v1",
            "independence": {
                "mechanism": "process_isolation",
                "assertion_pattern": FORBIDDEN_MODULE_RE.pattern,
                "resident_modules": modules,
                "resident_module_count": len(modules),
                "interpreter": sys.executable,
                "static_closure_test": "caprls_core.content_offline_checks:static_import_closure",
            },
            "reference_renderer_shared_with_candidate": False,
        }
    )
    return payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m caprls_core.content_reference",
        description="Emit one content-boundary reference relation, planner-free.",
    )
    parser.add_argument("--cell", default=None, help="cell_id or short_id")
    parser.add_argument("--root", default=None, help="repository root")
    parser.add_argument("--spec", default=None, help="path to specs/content_cells.yaml")
    parser.add_argument(
        "--emit-sql",
        action="store_true",
        help="emit the reference payload as JSON on stdout",
    )
    parser.add_argument(
        "--with-context",
        action="store_true",
        help="load the bound context row from public.synthetic_context (E2/E10)",
    )
    parser.add_argument(
        "--assert-isolation-only",
        action="store_true",
        help="run the sys.modules assertion and print the resident list, then exit",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.assert_isolation_only:
        modules = assert_isolated()
        json.dump(
            {
                "status": "isolated",
                "assertion_pattern": FORBIDDEN_MODULE_RE.pattern,
                "resident_modules": modules,
                "resident_module_count": len(modules),
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0

    if not args.emit_sql:
        parser.error("--emit-sql is required unless --assert-isolation-only is given")
    if not args.cell:
        parser.error("--cell is required with --emit-sql")

    root = _repo_root(args.root)
    spec_path = Path(args.spec) if args.spec else root / "specs" / "content_cells.yaml"
    try:
        payload = emit(
            cell_key=args.cell,
            root=root,
            spec_path=spec_path,
            needs_context=args.with_context,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed with a machine-readable refusal
        json.dump(
            {
                "status": "refused",
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 2
    payload["status"] = "ok"
    json.dump(payload, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
