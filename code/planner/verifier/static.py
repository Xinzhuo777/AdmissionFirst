"""Static plan-shape checks for implemented templates."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Optional


@dataclass(frozen=True)
class StaticVerification:
    status: str
    reasons: list[str]
    plan_hash: str


def _walk_plan_nodes(node: Any) -> Iterable[dict]:
    if isinstance(node, dict):
        if "Node Type" in node:
            yield node
        for value in node.values():
            yield from _walk_plan_nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_plan_nodes(item)


def _normalized_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip().lower())


def _plan_root(explain_json: Any, reasons: list[str]) -> dict[str, Any]:
    try:
        root = explain_json[0]["Plan"]
    except (KeyError, IndexError, TypeError):
        reasons.append("EXPLAIN JSON missing top-level Plan")
        return {}
    if not isinstance(root, dict):
        reasons.append("EXPLAIN JSON top-level Plan must be an object")
        return {}
    return root


def _nodes(plan_root: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(_walk_plan_nodes(plan_root))


def _has_node_type(nodes: Iterable[dict[str, Any]], node_type: str) -> bool:
    return any(str(node.get("Node Type")) == node_type for node in nodes)


def _cte_scan_names(nodes: Iterable[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for node in nodes:
        if str(node.get("Node Type")) == "CTE Scan":
            name = str(node.get("CTE Name", "")).lower()
            if name:
                names.add(name)
    return names


def _relation_names(nodes: Iterable[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for node in nodes:
        name = str(node.get("Relation Name", "")).lower()
        if name:
            names.add(name)
    return names


def _is_mav_relation(name: str) -> bool:
    return name.startswith("auth_mv_") or name.startswith("mav_") or "_mav_" in name


PLAN_CONDITION_FIELDS = (
    "Filter",
    "Index Cond",
    "Recheck Cond",
    "Hash Cond",
    "Merge Cond",
    "Join Filter",
)

NATIVE_RLS_FINGERPRINT_PREFIX = "caprls_native_rls_policy_fingerprint:"


def _condition_text(nodes: Iterable[dict[str, Any]]) -> str:
    fragments: list[str] = []
    for node in nodes:
        for field in PLAN_CONDITION_FIELDS:
            value = node.get(field)
            if value:
                fragments.append(str(value))
    return _normalized_sql(" ".join(fragments))


def _condition_fragments(nodes: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    fragments: list[str] = []
    for node in nodes:
        for field in PLAN_CONDITION_FIELDS:
            value = node.get(field)
            if value:
                fragments.append(_normalized_sql(str(value)))
    return tuple(fragments)


SQL_WHERE_END_RE = re.compile(
    r"\b(group\s+by|order\s+by|having|limit|union|intersect|except)\b|;"
)


def _where_condition_text(sql: str) -> str:
    fragments: list[str] = []
    for match in re.finditer(r"\bwhere\b", sql):
        start = match.end()
        end_match = SQL_WHERE_END_RE.search(sql, start)
        end = end_match.start() if end_match is not None else len(sql)
        fragments.append(sql[start:end])
    return _normalized_sql(" ".join(fragments))


def _policy_fingerprint_tokens(sql: str) -> tuple[str, ...]:
    sql = _where_condition_text(sql)
    tokens: list[str] = []
    for token in ("tenant_id", "owner_id", "region_id", "c_custkey", "t_id"):
        if re.search(rf"\b{re.escape(token)}\b", sql):
            tokens.append(token)
    if re.search(r"\bdoc_id\s*%", sql):
        tokens.extend(("doc_id", "100000"))
    if re.search(r"(?:\b[a-z_][\w]*\.)?public\s*(?:=|is)\s*true", sql):
        tokens.append("public")
    if re.search(r"(?:\b[a-z_][\w]*\.)?region\s*(?:=|<|>|in\b)", sql):
        tokens.append("region")
    if re.search(r"(?:\b[a-z_][\w]*\.)?class\s*(?:=|<|>)", sql):
        tokens.append("class")
    if "purpose_policy" in sql or re.search(r"\bpurpose\s*=", sql):
        tokens.append("purpose")

    ordered_unique: list[str] = []
    for token in tokens:
        if token not in ordered_unique:
            ordered_unique.append(token)
    return tuple(ordered_unique)


def native_rls_policy_fingerprint_comment(policy_predicate: str) -> str:
    tokens = _policy_fingerprint_tokens(f"where {policy_predicate}")
    return f"/* {NATIVE_RLS_FINGERPRINT_PREFIX} {','.join(tokens)} */"


def _native_rls_policy_fingerprint_tokens(sql: str) -> tuple[str, ...]:
    match = re.search(
        rf"/\*\s*{re.escape(NATIVE_RLS_FINGERPRINT_PREFIX)}\s*([^*]*)\*/",
        sql,
    )
    if match is None:
        return ()
    tokens: list[str] = []
    for token in re.split(r"[^a-z0-9_]+", match.group(1).lower()):
        if token and token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def _verify_policy_fingerprint(
    label: str,
    lower_sql: str,
    nodes: Iterable[dict[str, Any]],
    reasons: list[str],
) -> None:
    fingerprint_tokens = _policy_fingerprint_tokens(lower_sql)
    if not fingerprint_tokens:
        reasons.append(f"{label} SQL must expose a recognizable policy predicate fingerprint")
        return

    conditions = _condition_text(nodes)
    if not conditions:
        reasons.append(f"{label} EXPLAIN conditions must contain policy predicate fingerprint")
        return
    missing = _missing_fragments(conditions, fingerprint_tokens)
    if missing:
        reasons.append(
            f"{label} EXPLAIN conditions must contain policy predicate fingerprint: "
            + ", ".join(missing)
        )


def _missing_fragments(text: str, fragments: Iterable[str]) -> tuple[str, ...]:
    return tuple(fragment for fragment in fragments if fragment not in text)


def _has_join(nodes: Iterable[dict[str, Any]]) -> bool:
    for node in nodes:
        node_type = str(node.get("Node Type"))
        if "Join" in node_type or node_type == "Nested Loop":
            return True
    return False


def _has_materialized_cte(sql: str, name: str) -> bool:
    return f"with {name} as materialized" in sql or f", {name} as materialized" in sql


def _has_not_materialized_cte(sql: str, name: str) -> bool:
    return f"with {name} as not materialized" in sql or f", {name} as not materialized" in sql


_EXACT_BOUND_RUNNER_PREFIX_RE = re.compile(
    r"\A\s*with\s+caprls_access_root\s+as\s+(?:not\s+)?materialized\s*\(",
    re.IGNORECASE,
)


def _exact_bound_runner_fingerprint_scope(
    sql: str,
) -> tuple[bool, Optional[str]]:
    """Return the strict-core fingerprint scope for one exact F1 wrapper.

    A recognized but malformed wrapper returns ``(True, None)``.  Callers
    must reject that result and must never fall back to fingerprinting the
    complete runner, which also contains the semantic continuation.
    """

    prefix = _EXACT_BOUND_RUNNER_PREFIX_RE.match(sql)
    if prefix is None:
        return False, None
    opening = prefix.end() - 1
    if opening < 0 or sql[opening] != "(":
        return True, None
    depth = 1
    closing: Optional[int] = None
    in_single_quote = False
    index = opening + 1
    while index < len(sql):
        character = sql[index]
        if in_single_quote:
            if character != "'":
                index += 1
                continue
            if index + 1 < len(sql) and sql[index + 1] == "'":
                index += 2
                continue
            in_single_quote = False
            index += 1
            continue
        if character == "'":
            in_single_quote = True
            index += 1
            continue
        if (
            character in {'"', "$"}
            or sql.startswith("--", index)
            or sql.startswith("/*", index)
        ):
            return True, None
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
        index += 1
    if closing is None or in_single_quote:
        return True, None

    core_sql = sql[opening + 1 : closing].strip()
    continuation_sql = sql[closing + 1 :].strip()
    if not core_sql or not continuation_sql:
        return True, None
    continuation_head = _normalized_sql(continuation_sql)
    if not (
        continuation_head.startswith("select ")
        or continuation_head.startswith(",")
    ):
        return True, None
    return True, _normalized_sql(core_sql)


def _has_unexpected_inline_cte_scan(
    nodes: Iterable[dict[str, Any]],
    *,
    allow_bound_runner_wrapper: bool,
) -> bool:
    for node in nodes:
        if str(node.get("Node Type")) != "CTE Scan":
            continue
        if (
            not allow_bound_runner_wrapper
            or str(node.get("CTE Name", "")).lower() != "caprls_access_root"
        ):
            return True
    return False


def _cte_select_list_contains_star(sql: str, name: str) -> bool:
    match = re.search(
        rf"\b{re.escape(name)}\s+as\s+(?:not\s+)?materialized\s*\(\s*select\s+(.*?)\s+from\s",
        sql,
    )
    return bool(match and "*" in match.group(1))


def _guard_outer_where_text(lower_sql: str, guard_names: Iterable[str]) -> str:
    start_offsets: list[int] = []
    for name in guard_names:
        for match in re.finditer(rf"\bfrom\s+{re.escape(name)}\b", lower_sql):
            start_offsets.append(match.end())
    if not start_offsets:
        return ""
    start = min(start_offsets)
    where_match = re.search(r"\bwhere\b", lower_sql[start:])
    if where_match is None:
        return ""
    where_start = start + where_match.end()
    end_match = SQL_WHERE_END_RE.search(lower_sql, where_start)
    where_end = end_match.start() if end_match is not None else len(lower_sql)
    return lower_sql[where_start:where_end]


def _verify_guard_unsafe_order(
    lower_sql: str,
    guard_names: Iterable[str],
    nodes: Iterable[dict[str, Any]],
    reasons: list[str],
) -> None:
    if "unsafe_log" not in lower_sql:
        return
    outer_where = _guard_outer_where_text(lower_sql, guard_names)
    residual_tokens = _policy_fingerprint_tokens(f"where {outer_where}")
    if not residual_tokens:
        reasons.append("Guard+LateResidual unsafe UDF path must expose a late residual fingerprint")
        return
    unsafe_conditions = [
        condition
        for condition in _condition_fragments(nodes)
        if "unsafe_log" in condition
    ]
    if not unsafe_conditions:
        reasons.append("Guard+LateResidual EXPLAIN conditions must contain unsafe UDF call")
        return
    missing_by_condition: list[tuple[str, ...]] = []
    for condition in unsafe_conditions:
        unsafe_at = condition.find("unsafe_log")
        missing = tuple(
            token
            for token in residual_tokens
            if token not in condition or condition.find(token) > unsafe_at
        )
        if not missing:
            return
        missing_by_condition.append(missing)
    shortest_missing = min(missing_by_condition, key=len)
    reasons.append(
        "Guard+LateResidual EXPLAIN unsafe UDF condition must show residual "
        "fingerprint before unsafe_log: "
        + ", ".join(shortest_missing)
    )


def _finish(reasons: list[str], plan_hash: str) -> StaticVerification:
    status = "pass" if not reasons else "fail"
    return StaticVerification(status=status, reasons=reasons, plan_hash=plan_hash)


def verify_barrier_filter_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if not _has_materialized_cte(lower_sql, "auth"):
        reasons.append("BarrierFilter must use a MATERIALIZED auth CTE")
    if _cte_select_list_contains_star(lower_sql, "auth"):
        reasons.append("BarrierFilter auth CTE must use an explicit carrier projection, not *")
    if " as __rid" not in lower_sql:
        reasons.append("BarrierFilter must preserve hidden RID carrier as __rid")
    if " where " not in lower_sql:
        reasons.append("BarrierFilter auth CTE must contain an exact policy predicate")

    plan_root = _plan_root(explain_json, reasons)
    if "auth" not in _cte_scan_names(_nodes(plan_root)):
        reasons.append("EXPLAIN plan does not contain a CTE Scan for auth")

    return _finish(reasons, plan_hash)


def _parenthesized_sql_body(sql: str, opening: int) -> Optional[tuple[str, int]]:
    """Extract one controlled-emitter operand without crossing its scope.

    This is a shape parser for the finite SQL lowering, not a general SQL
    parser. Unsupported lexical forms fail closed. Single-quoted literals
    may contain escaped quotes and parentheses.
    """

    if opening >= len(sql) or sql[opening] != "(":
        return None
    depth = 1
    in_quote = False
    index = opening + 1
    while index < len(sql):
        char = sql[index]
        if in_quote:
            if char == "'":
                if index + 1 < len(sql) and sql[index + 1] == "'":
                    index += 2
                    continue
                in_quote = False
        elif char == "'":
            in_quote = True
        elif char in {'"', "$"} or sql.startswith(("--", "/*"), index):
            return None
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return sql[opening + 1:index], index + 1
        index += 1
    return None


def _query_filtered_barrier_operands(body: str) -> Optional[tuple[str, str]]:
    where = re.search(r"\bwhere\s+", body)
    if where is None:
        return None
    condition = body[where.end():].strip()
    exact = _parenthesized_sql_body(condition, 0)
    if exact is None or not exact[0].strip():
        return None
    remaining = condition[exact[1]:].strip()
    conjunction = re.match(r"and\s+", remaining)
    if conjunction is None:
        return None
    query = _parenthesized_sql_body(remaining, conjunction.end())
    if query is None or not query[0].strip() or remaining[query[1]:].strip():
        return None
    return exact[0], query[0]


def _query_filtered_deferred_rid_is_preserved(
    projection: str, suffix: str, cte_name: str,
) -> bool:
    """Recognize only the controlled equal-column alias outside auth.

    The producer must retain every explicitly named base carrier. The exact
    RID identity is bound by the strict emitter/certificate and checked root
    schema; this shape check additionally excludes an expression, missing
    column, different CTE, or an alias mentioned only inside a literal.
    """
    identifier = r"[a-z_][a-z0-9_]*"
    column = rf"{identifier}\.{identifier}"
    if re.fullmatch(rf"select\s+{column}(?:\s*,\s*{column})*", projection) is None:
        return False
    projected = re.findall(rf"\b({identifier})\.({identifier})\b", projection)
    if len({alias for alias, _ in projected}) != 1:
        return False
    columns = {name for _, name in projected}
    without_literals = re.sub(r"'(?:[^']|'')*'", "''", suffix)
    name = re.escape(cte_name)
    restores = re.findall(
        rf"\bselect\s+{name}\.\*\s*,\s*{name}\.({identifier})\s+as\s+__rid\s+"
        rf"from\s+{name}\b(?=\s*(?:\)|;|$))",
        without_literals,
    )
    return len(restores) == 1 and restores[0] in columns


def verify_barrier_filter_query_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    wrapped, core = _exact_bound_runner_fingerprint_scope(sql)
    if wrapped and core is None:
        return _finish(["QueryFilteredBarrierFilter exact bound-runner wrapper is malformed"], plan_hash)
    scoped_sql = core if wrapped else _normalized_sql(sql)
    assert scoped_sql is not None
    definitions = tuple(re.finditer(
        r"(?:\bwith|,)\s+(auth(?:_[a-z0-9_]+)?)\s+as\s+materialized\s*\(",
        scoped_sql,
    ))
    if not definitions:
        reasons.append("QueryFilteredBarrierFilter must use a MATERIALIZED auth CTE")
    root = _plan_root(explain_json, reasons)
    nodes = _nodes(root)
    scan_names = _cte_scan_names(nodes)
    for definition in definitions:
        name = definition.group(1)
        parsed = _parenthesized_sql_body(scoped_sql, definition.end() - 1)
        if parsed is None:
            reasons.append(f"QueryFilteredBarrierFilter {name} CTE is malformed")
            continue
        body = parsed[0]
        if _cte_select_list_contains_star(scoped_sql, name):
            reasons.append("QueryFilteredBarrierFilter auth CTE must use an explicit carrier projection, not *")
        projection = body.split(" from ", 1)[0]
        if " as __rid" not in projection and not _query_filtered_deferred_rid_is_preserved(
            projection, scoped_sql[parsed[1]:], name,
        ):
            reasons.append("QueryFilteredBarrierFilter must preserve hidden RID carrier as __rid in auth or its exact output projection")
        operands = _query_filtered_barrier_operands(body)
        if operands is None:
            reasons.append("QueryFilteredBarrierFilter auth CTE must conjoin parenthesized exact policy and query predicates")
            continue
        if any(re.search(r"<\w+>", operand) for operand in operands):
            reasons.append("QueryFilteredBarrierFilter predicates must be concrete")
        if name not in scan_names:
            reasons.append(f"EXPLAIN plan does not contain a CTE Scan for {name}")
        producers = tuple(
            node for node in nodes
            if str(node.get("Subplan Name", "")).lower() == "cte " + name
        )
        if len(producers) != 1:
            reasons.append(f"QueryFilteredBarrierFilter EXPLAIN must identify one producer for {name}")
            continue
        producer_nodes = _nodes(producers[0])
        # Restrict both SQL and EXPLAIN scope: an outer filter or semantic
        # continuation cannot stand in for policy evaluation inside auth.
        _verify_policy_fingerprint(
            "QueryFilteredBarrierFilter inner policy", "where " + operands[0],
            producer_nodes, reasons,
        )
        query_without_literals = re.sub(r"'(?:[^']|'')*'", "''", operands[1])
        table_names = set(re.findall(r"\b(?:from|join)\s+([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)",query_without_literals))
        query_columns = {match.group(2) for match in re.finditer(
            r"\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b(?!\s*\()",query_without_literals)
            if match.group(0) not in table_names}
        missing_query = _missing_fragments(_condition_text(producer_nodes), sorted(query_columns))
        if missing_query:
            reasons.append("QueryFilteredBarrierFilter inner producer must contain query predicate columns: " + ", ".join(missing_query))
    return _finish(reasons, plan_hash)


def verify_barrier_filter_inline_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if not _has_not_materialized_cte(lower_sql, "auth"):
        reasons.append("InlineBarrierFilter must use a NOT MATERIALIZED auth CTE")
    if _cte_select_list_contains_star(lower_sql, "auth"):
        reasons.append("InlineBarrierFilter auth CTE must use an explicit carrier projection, not *")
    if " as __rid" not in lower_sql:
        reasons.append("InlineBarrierFilter must preserve hidden RID carrier as __rid")
    if " where " not in lower_sql:
        reasons.append("InlineBarrierFilter auth CTE must contain an exact policy predicate")

    plan_root = _plan_root(explain_json, reasons)
    if "auth" in _cte_scan_names(_nodes(plan_root)):
        reasons.append("InlineBarrierFilter must not materialize auth as a CTE Scan")
    return _finish(reasons, plan_hash)


def verify_safe_predicate_injection_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    bound_runner_wrapper, fingerprint_sql = (
        _exact_bound_runner_fingerprint_scope(sql)
    )
    if bound_runner_wrapper and fingerprint_sql is None:
        reasons.append(
            "SafePredicateInjection exact bound-runner wrapper is malformed"
        )
    if lower_sql.startswith("with ") and not bound_runner_wrapper:
        reasons.append("SafePredicateInjection must be an inline SELECT, not a CTE pipeline")
    if " where " not in lower_sql:
        reasons.append("SafePredicateInjection must contain an exact policy predicate")
    if " and " not in lower_sql:
        reasons.append("SafePredicateInjection must conjoin ordinary-safe and exact policy predicates")
    if "auth_idx" in lower_sql or "auth_mv" in lower_sql:
        reasons.append("SafePredicateInjection must not read authorization artifacts")

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    if _has_unexpected_inline_cte_scan(
        nodes,
        allow_bound_runner_wrapper=bound_runner_wrapper,
    ):
        reasons.append("SafePredicateInjection EXPLAIN plan must not contain a CTE Scan")
    if not bound_runner_wrapper:
        fingerprint_sql = lower_sql
    if fingerprint_sql is not None:
        _verify_policy_fingerprint(
            "SafePredicateInjection",
            fingerprint_sql,
            nodes,
            reasons,
        )
    return _finish(reasons, plan_hash)


def verify_native_pg_rls_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if "auth_idx" in lower_sql or "auth_mv" in lower_sql:
        reasons.append("NativePG-RLS must not embed CAPRLS artifact or auth CTE SQL")
    if "<exact_policy>" in lower_sql or "<safe_query>" in lower_sql:
        reasons.append("NativePG-RLS SQL must leave authorization to the engine policy")

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    if not nodes:
        reasons.append("NativePG-RLS EXPLAIN plan must contain at least one plan node")
    policy_tokens = _native_rls_policy_fingerprint_tokens(lower_sql)
    if not policy_tokens:
        reasons.append("NativePG-RLS SQL must carry expected RLS policy fingerprint metadata")
    else:
        conditions = _condition_text(nodes)
        if not conditions:
            reasons.append("NativePG-RLS EXPLAIN conditions must contain RLS policy qual")
        else:
            missing = _missing_fragments(conditions, policy_tokens)
            if missing:
                reasons.append(
                    "NativePG-RLS EXPLAIN conditions must contain RLS policy qual: "
                    + ", ".join(missing)
                )
    return _finish(reasons, plan_hash)


def verify_ordinary_first_exact_check_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    bound_runner_wrapper, fingerprint_sql = (
        _exact_bound_runner_fingerprint_scope(sql)
    )
    if bound_runner_wrapper and fingerprint_sql is None:
        reasons.append(
            "OrdinaryFirstExactCheck exact bound-runner wrapper is malformed"
        )
    if lower_sql.startswith("with ") and not bound_runner_wrapper:
        reasons.append("OrdinaryFirstExactCheck must be an inline SELECT")
    if " where " not in lower_sql or " and " not in lower_sql:
        reasons.append("OrdinaryFirstExactCheck must conjoin ordinary predicate and exact policy")
    if "auth_idx" in lower_sql or "auth_mv" in lower_sql:
        reasons.append("OrdinaryFirstExactCheck must not read authorization artifacts")

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    if _has_unexpected_inline_cte_scan(
        nodes,
        allow_bound_runner_wrapper=bound_runner_wrapper,
    ):
        reasons.append("OrdinaryFirstExactCheck EXPLAIN plan must not contain a CTE Scan")
    if not bound_runner_wrapper:
        fingerprint_sql = lower_sql
    if fingerprint_sql is not None:
        _verify_policy_fingerprint(
            "OrdinaryFirstExactCheck",
            fingerprint_sql,
            nodes,
            reasons,
        )
    return _finish(reasons, plan_hash)


def verify_auth_view_scan_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if "auth_view_" not in lower_sql:
        reasons.append("AuthorizationViewScan must read an auth_view_* relation")
    if "auth_idx" in lower_sql or "auth_mv" in lower_sql:
        reasons.append("AuthorizationViewScan must not read auth_idx or auth_mv artifacts")

    plan_root = _plan_root(explain_json, reasons)
    relations = _relation_names(_nodes(plan_root))
    if not any(name.startswith("auth_view_") for name in relations):
        reasons.append("AuthorizationViewScan EXPLAIN plan must scan an auth_view_* relation")
    return _finish(reasons, plan_hash)


def _verify_auth_index_static(
    *,
    label: str,
    sql: str,
    explain_json: Any,
    plan_hash: str,
    table: str,
    semijoin: bool,
    keyed: bool,
) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if table not in lower_sql:
        reasons.append(f"{label} must read {table}")
    if semijoin:
        if " exists " not in lower_sql and " exists(" not in lower_sql:
            reasons.append(f"{label} must use EXISTS semijoin shape")
    elif " join " not in lower_sql or " on " not in lower_sql:
        reasons.append(f"{label} must join {table} to the protected relation")
    if keyed and ("key_name" not in lower_sql or "key_value" not in lower_sql):
        reasons.append(f"{label} must constrain key_name and key_value")
    sql_scope_required = ("artifact_id", "ctx_hash", "rid_domain_id", "base_rel_oid")
    missing_sql_scope = _missing_fragments(lower_sql, sql_scope_required)
    if missing_sql_scope:
        reasons.append(
            f"{label} must constrain artifact scope in SQL: {', '.join(missing_sql_scope)}"
        )
    if "rid" not in lower_sql:
        reasons.append(f"{label} SQL must join or correlate on the declared RID carrier")

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    if table not in _relation_names(nodes):
        reasons.append(f"{label} EXPLAIN plan must scan {table}")
    if not _has_join(nodes):
        reasons.append(f"{label} EXPLAIN plan must join against {table}")
    conditions = _condition_text(nodes)
    missing_plan_scope = _missing_fragments(conditions, ("artifact_id", "ctx_hash", "rid_domain_id"))
    if missing_plan_scope:
        reasons.append(
            f"{label} EXPLAIN conditions must enforce artifact scope: "
            + ", ".join(missing_plan_scope)
        )
    if "rid" not in conditions:
        reasons.append(f"{label} EXPLAIN conditions must contain RID join/correlation evidence")
    return _finish(reasons, plan_hash)


def verify_auth_index_enum_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    return _verify_auth_index_static(
        label="AuthorizationIndexSeek",
        sql=sql,
        explain_json=explain_json,
        plan_hash=plan_hash,
        table="auth_idx",
        semijoin=False,
        keyed=False,
    )


def verify_auth_index_semijoin_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    return _verify_auth_index_static(
        label="AuthorizationIndexSemiJoin",
        sql=sql,
        explain_json=explain_json,
        plan_hash=plan_hash,
        table="auth_idx",
        semijoin=True,
        keyed=False,
    )


def verify_strong_auth_index_keyed_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    return _verify_auth_index_static(
        label="StrongAuthorizationIndexKeyed",
        sql=sql,
        explain_json=explain_json,
        plan_hash=plan_hash,
        table="auth_idx_keyed",
        semijoin=False,
        keyed=True,
    )


def verify_auth_index_keyed_semijoin_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    return _verify_auth_index_static(
        label="AuthorizationIndexKeyedSemiJoin",
        sql=sql,
        explain_json=explain_json,
        plan_hash=plan_hash,
        table="auth_idx_keyed",
        semijoin=True,
        keyed=True,
    )


def verify_mav_scan_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if "auth_mv_" not in lower_sql and "mav_" not in lower_sql:
        reasons.append("MaterializedAuthorizedViewScan must read an auth_mv_* or mav_* relation")
    if "auth_idx" in lower_sql:
        reasons.append("MaterializedAuthorizedViewScan must not read auth_idx")
    required_binding_fragments = (
        "caprls_catalog.artifact_catalog",
        "caprls_catalog.rid_domain",
        "ac.artifact_id =",
        "ac.materialized_rel =",
        "ac.relname =",
        "ac.policy_id =",
        "ac.user_scope",
        "ac.query_scope_hash",
        "ac.rid_domain_id =",
        "rd.base_rel_oid =",
    )
    missing_binding = _missing_fragments(lower_sql, required_binding_fragments)
    if missing_binding:
        reasons.append(
            "MaterializedAuthorizedViewScan SQL must bind MAV relation to artifact scope: "
            + ", ".join(missing_binding)
        )

    plan_root = _plan_root(explain_json, reasons)
    relations = _relation_names(_nodes(plan_root))
    if not any(_is_mav_relation(name) for name in relations):
        reasons.append("MaterializedAuthorizedViewScan EXPLAIN plan must scan an auth_mv_* or mav_* relation")
    missing_binding_relations = {
        name for name in ("artifact_catalog", "rid_domain") if name not in relations
    }
    if missing_binding_relations:
        reasons.append(
            "MaterializedAuthorizedViewScan EXPLAIN plan must scan catalog binding relations: "
            + ", ".join(sorted(missing_binding_relations))
        )
    binding_relations = {"artifact_catalog", "rid_domain"}
    non_mav_relations = sorted(
        name
        for name in relations
        if not _is_mav_relation(name) and name not in binding_relations
    )
    if non_mav_relations:
        reasons.append(
            "MaterializedAuthorizedViewScan EXPLAIN plan must not scan base relations: "
            + ", ".join(non_mav_relations)
        )
    return _finish(reasons, plan_hash)


def verify_guard_candidate_plus_residual_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    guard_names = ("cand", "guard_candidate")
    if not any(_has_materialized_cte(lower_sql, name) for name in guard_names):
        reasons.append("Guard+LateResidual must use a MATERIALIZED guard candidate CTE")
    if any(_cte_select_list_contains_star(lower_sql, name) for name in guard_names):
        reasons.append("Guard+LateResidual candidate CTE must use an explicit carrier projection, not *")
    if " as __rid" not in lower_sql:
        reasons.append("Guard+LateResidual must preserve hidden RID carrier as __rid")
    if lower_sql.count(" where ") < 2:
        reasons.append("Guard+LateResidual must separate complete guard and late exact residual predicates")

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    cte_names = _cte_scan_names(nodes)
    if not any(name in cte_names for name in guard_names):
        reasons.append("Guard+LateResidual EXPLAIN plan must contain a CTE Scan for the guard candidate")
    _verify_guard_unsafe_order(lower_sql, guard_names, nodes, reasons)
    return _finish(reasons, plan_hash)


def verify_hybrid_intersect_static(sql: str, explain_json: Any, plan_hash: str) -> StaticVerification:
    reasons: list[str] = []
    lower_sql = _normalized_sql(sql)
    if lower_sql.count(" as materialized") < 2:
        reasons.append("HybridIndexIntersect must materialize query and authorization RID inputs")
    if "auth_idx" not in lower_sql:
        reasons.append("HybridIndexIntersect must read auth_idx")
    if " join " not in lower_sql:
        reasons.append("HybridIndexIntersect must join query RIDs with authorization RIDs")
    missing_sql_scope = _missing_fragments(
        lower_sql,
        ("artifact_id", "ctx_hash", "rid_domain_id", "base_rel_oid"),
    )
    if missing_sql_scope:
        reasons.append(
            "HybridIndexIntersect must constrain authorization artifact scope in SQL: "
            + ", ".join(missing_sql_scope)
        )

    plan_root = _plan_root(explain_json, reasons)
    nodes = _nodes(plan_root)
    if "auth_idx" not in _relation_names(nodes):
        reasons.append("HybridIndexIntersect EXPLAIN plan must scan auth_idx")
    if not _has_join(nodes):
        reasons.append("HybridIndexIntersect EXPLAIN plan must contain a join")
    conditions = _condition_text(nodes)
    missing_plan_scope = _missing_fragments(conditions, ("artifact_id", "ctx_hash", "rid_domain_id"))
    if missing_plan_scope:
        reasons.append(
            "HybridIndexIntersect EXPLAIN conditions must enforce authorization artifact scope: "
            + ", ".join(missing_plan_scope)
        )
    if "rid" not in conditions:
        reasons.append("HybridIndexIntersect EXPLAIN conditions must contain RID intersection evidence")
    return _finish(reasons, plan_hash)


TemplateStaticVerifier = Callable[[str, Any, str], StaticVerification]


TEMPLATE_STATIC_VERIFIERS: Mapping[str, TemplateStaticVerifier] = MappingProxyType(
    {
        "barrier_filter_v1": verify_barrier_filter_static,
        "barrier_filter_query_v1": verify_barrier_filter_query_static,
        "barrier_filter_continuation_v1": verify_barrier_filter_query_static,
        "barrier_filter_inline_v1": verify_barrier_filter_inline_static,
        "safe_predicate_injection_v1": verify_safe_predicate_injection_static,
        "native_pg_rls_v1": verify_native_pg_rls_static,
        "ordinary_first_exact_check_v1": verify_ordinary_first_exact_check_static,
        "auth_view_scan_v1": verify_auth_view_scan_static,
        "auth_index_enum_v1": verify_auth_index_enum_static,
        "auth_index_semijoin_v1": verify_auth_index_semijoin_static,
        "strong_auth_index_keyed_v1": verify_strong_auth_index_keyed_static,
        "auth_index_keyed_semijoin_v1": verify_auth_index_keyed_semijoin_static,
        "mav_scan_v1": verify_mav_scan_static,
        "guard_candidate_plus_residual_v1": verify_guard_candidate_plus_residual_static,
        "hybrid_intersect_v1": verify_hybrid_intersect_static,
    }
)


def verify_template_static(
    template_id: str, sql: str, explain_json: Any, plan_hash: str
) -> StaticVerification:
    verifier = TEMPLATE_STATIC_VERIFIERS.get(template_id)
    if verifier is None:
        return StaticVerification(
            status="fail",
            reasons=[f"no static verifier registered for template: {template_id}"],
            plan_hash=plan_hash,
        )
    return verifier(sql, explain_json, plan_hash)


def explain_json_from_text(payload: str) -> Any:
    return json.loads(payload)
