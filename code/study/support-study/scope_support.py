"""Read-only bridge for R08's canonical CTE scope; no SQL runs on import.

Detached parsing/digests issue no authority. Callers must first retain the
source-native worker's original owned replay and physical/profile audits.
"""
from contextlib import contextmanager
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys


PARSER_SHA = "sha256:bc60e6003799082402c3e6956a0c7e06b82b584126662bea1af80ec4fc8aeaba"
LEXER_SHA = "sha256:bd31c344fa5965173db30c9fe41460abd45107693232e8d95b91711f447115fd"
_ABSENT = object()


def sha(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def source_parser(source):
    """Temporarily bind the exact pure parser for source-auditor imports.

    CONTENT keeps its project-side verifier. Its already-loaded lexer must
    therefore be byte-identical to the frozen source. A fresh parser ignores
    any existing module object; the prior module table is restored on exit.
    No runtime planner, admission class or object registry is substituted.
    """
    source = Path(source).resolve()
    path = source / "planner/pc_scope.py"
    if sha(path) != PARSER_SHA or sha(source / "planner/continuation_necessity.py") != LEXER_SHA:
        raise ValueError("support scope parser source differs from frozen R08")
    lexer = importlib.import_module("planner.continuation_necessity")
    if sha(lexer.__file__) != LEXER_SHA:
        raise ValueError("support project lexer differs from the frozen parser dependency")
    name = "planner.pc_scope"
    previous = sys.modules.get(name, _ABSENT)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("source scope parser is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[name] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        if previous is _ABSENT:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


def bound_core(sql, bound, parser):
    """Recover the original closed core, verifying all exact digest links.

    Legacy extraction is contiguous. A lifted PC requires verbatim CTE
    fragments to be reclosed with WITH, then matched to the original strict
    core digest. Its distinct fidelity is retained in the proof.
    """
    if type(sql) is not str or type(bound) is not dict or bound.get("runner_sql") != sql:
        raise ValueError("scope extraction lacks its exact bound runner")
    runner_digest = digest({"exact_runner_sql": sql})
    if bound.get("runner_sql_digest") != runner_digest:
        raise ValueError("scope extraction complete runner digest differs")
    materialized = parser.decode_access_root_materialized(sql)
    if materialized is None or not sql.startswith("WITH "):
        raise ValueError("scope extraction requires a canonical access-root composition")
    pos, entries = len("WITH"), []
    while len(entries) < 3:
        header = parser._HEADER.match(sql, pos)
        if header is None:
            raise ValueError("scope extraction CTE header is not canonical")
        end = parser._closing_paren(sql, header.end())
        if end is None:
            raise ValueError("scope extraction CTE is unbalanced")
        entries.append({"name": header.group(1), "body": sql[header.end():end],
                        "text": sql[pos:end + 1].strip(), "start": header.end(), "end": end})
        pos = end + 1
        look = pos
        while look < len(sql) and sql[look].isspace():
            look += 1
        if sql[look:look + 1] != ",":
            break
        pos = look + 1
    names = [entry["name"] for entry in entries]
    if names == ["caprls_access_root"]:
        root, prelude, boundary = entries[0], None, entries[0]["body"]
        fidelity = "verbatim_subplan_planner_anchored"
        extraction = "actual_bound_access_root"
    elif names == ["auth", "caprls_access_root"]:
        if bound.get("template_id") != "barrier_filter_query_v1":
            raise ValueError("lifted producer is not the bound PC template")
        root, prelude = entries[1], entries[0]["text"]
        boundary = "\nWITH " + prelude + root["body"]
        fidelity = "verbatim_cte_fragments_reclosed_planner_anchored"
        extraction = "actual_bound_cte_fragments_with_original_core_digest"
    else:
        raise ValueError("scope extraction has an unsupported CTE inventory")
    core = boundary.strip()
    core_digest = digest({"strict_core_sql": core})
    if bound.get("strict_core_sql_digest") != core_digest:
        raise ValueError("recovered closed core differs from the original strict digest")
    continuation = sql[root["end"] + 1:]
    if bound.get("continuation_sql_digest") != digest({"exact_continuation_sql": continuation}):
        raise ValueError("scope extraction changed the exact bound continuation")
    prefix, suffix = sql[:root["start"]], sql[root["end"]:]
    if prefix + root["body"] + suffix != sql:
        raise ValueError("scope extraction cannot recompose the exact complete runner")
    return boundary, {
        "fidelity": fidelity, "extraction": extraction,
        "verbatim_cte_prelude": prelude, "actual_access_root_body": root["body"],
        "recomposition_byte_identical": True,
        "wrapper_prefix": prefix, "continuation_suffix": suffix,
        "strict_core_sql_digest": core_digest,
        "original_core_sql_digest_verified": True,
        "complete_runner_sql_digest_verified": True,
        "continuation_sql_digest_verified": True,
        "actual_access_root_materialized": materialized,
        "scope_parser_source_sha256": PARSER_SHA,
        "closure_scope": "original registered core, not a newly rendered authorization query",
    }
