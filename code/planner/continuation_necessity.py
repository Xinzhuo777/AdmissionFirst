"""Replayable necessity proofs for a finite, typed continuation fragment.

The checked theorem preserves W's joined bag for every input subbag X under
filter_D.  D comes from actual inner-join witnesses/conjunctive qualifications;
q remains independently bound.  Fixed post-join operators receive that same
bag; their authorization stage, tie contract and partial/error-trace semantics
remain separate obligations.  A report is detached JSON.  Issuing or
replaying evidence additionally requires a currently registered, exact-SQL
ContinuationSpec.  This module issues neither Gamma facts nor catalog/type or
runtime authorization capabilities.  Its recorded builtin schema assumptions
must be validated by a production adapter before admission can consume it.

Supported SQL uses one caprls_access_root, ordinary public tables, equality
joins, and total builtin comparison/BETWEEN qualifications.  No raw expression,
safe=True assertion, arbitrary subquery, outer/anti join, or pre-input LIMIT is
part of this grammar.  Top-level result grouping/order/LIMIT is bound exactly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import date
import hashlib
import json
import re
from typing import Any, Mapping
import weakref

from .contracts import PolicyAccessTarget, canonical_predicate_digest


class NecessityError(ValueError):
    """Unsupported syntax, stale binding, or invalid proof provenance."""


_IDENT = re.compile(r"[a-z_][a-z0-9_]*\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KINDS = frozenset({"bigint", "integer", "text", "date", "numeric", "boolean"})
_NUMERIC = frozenset({"bigint", "integer", "numeric"})
# Conservative PG16 reserved/special-expression exclusion for unquoted names.
# https://www.postgresql.org/docs/16/sql-keywords-appendix.html
_SPECIAL_NAMES = frozenset("""
all analyse analyze and any array as asc asymmetric authorization binary both
case cast check collate collation column concurrently constraint create cross
current_catalog current_date current_role current_schema current_time
current_timestamp current_user default deferrable desc distinct do else end
except false fetch for foreign freeze from full grant group having ilike in
initially inner intersect into is isnull join lateral leading left like limit
localtime localtimestamp natural not notnull null offset on only or order outer
overlaps placing primary references returning right select session_user similar
some symmetric system_user table tablesample then to trailing true union unique user using
variadic verbose when where window with
""".split())
_TOKEN = re.compile(r"'(?:''|[^'])*'|[A-Za-z_][A-Za-z_0-9]*|[0-9]+(?:\.[0-9]+)?|::|<=|>=|<>|[().,*=<>+\-]")
_SOURCE_TOKEN = object()
_EVIDENCE_TOKEN = object()


def _fail(message: str) -> None:
    raise NecessityError(message)


def _ident(value: Any) -> str:
    if type(value) is not str or _IDENT.fullmatch(value) is None or len(value) > 63 or value in _SPECIAL_NAMES:
        _fail("finite SQL identifiers must be lowercase, unquoted identifiers")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        _fail(label + " must be a nonempty exact, trimmed string")
    return value


def _tuple(value: Any, cls: type, label: str, *, empty: bool = True) -> tuple:
    if type(value) is not tuple or any(type(item) is not cls for item in value):
        _fail(label + " must contain exact typed nodes in a tuple")
    if not empty and not value:
        _fail(label + " cannot be empty")
    return value


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode()).hexdigest()


def _sql_tokens(sql: str) -> tuple[str, ...]:
    """Finite lexer: preserve quoted literals, reject comments/unknown syntax."""
    if type(sql) is not str or not sql:
        _fail("continuation SQL must be an exact nonempty string")
    tokens: list[str] = []
    pos = 0
    while pos < len(sql):
        if sql[pos].isspace():
            pos += 1
            continue
        if sql.startswith(("--", "/*"), pos):
            _fail("comments are outside the finite SQL binding grammar")
        match = _TOKEN.match(sql, pos)
        if match is None:
            _fail("unsupported SQL token at offset " + str(pos))
        token = match.group()
        tokens.append(token if token.startswith("'") else token.lower())
        pos = match.end()
    return tuple(tokens)


@dataclass(frozen=True)
class ColumnType:
    name: str
    type_name: str
    collation: str | None = None
    typmod: int = -1


@dataclass(frozen=True)
class ProtectedInput:
    alias: str
    rid_column: str
    columns: tuple[ColumnType, ...]


@dataclass(frozen=True)
class OrdinaryRelation:
    name: str
    alias: str
    columns: tuple[ColumnType, ...]
    schema: str = "public"
    alias_with_as: bool = True


@dataclass(frozen=True)
class Column:
    alias: str
    name: str


@dataclass(frozen=True)
class Literal:
    type_name: str
    value: Any


@dataclass(frozen=True)
class Parameter:
    name: str


@dataclass(frozen=True)
class TypedParameter:
    name: str
    type_name: str
    value: Any


@dataclass(frozen=True)
class Arithmetic:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True)
class Compare:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True)
class Between:
    value: Any
    lower: Any
    upper: Any


@dataclass(frozen=True)
class Conjunct:
    predicate_id: str
    predicate: Any


@dataclass(frozen=True)
class InnerJoin:
    relation: OrdinaryRelation
    on: tuple[Conjunct, ...]


@dataclass(frozen=True)
class Aggregate:
    name: str
    argument: Any = None
    filter: Any = None


@dataclass(frozen=True)
class Year:
    value: Any


@dataclass(frozen=True)
class OutputName:
    name: str


@dataclass(frozen=True)
class SelectItem:
    expression: Any
    alias: str | None = None


@dataclass(frozen=True)
class OrderKey:
    expression: Any
    descending: bool = False


@dataclass(frozen=True)
class ContinuationQuery:
    protected: ProtectedInput
    joins: tuple[InnerJoin, ...]
    where: tuple[Conjunct, ...]
    select: tuple[SelectItem, ...]
    group_by: tuple[Any, ...] = ()
    order_by: tuple[OrderKey, ...] = ()
    limit: int | None = None


@dataclass(frozen=True)
class NecessityBindings:
    target: PolicyAccessTarget
    rid_column: str
    snapshot_id: str
    gamma_snapshot_digest: str
    q_predicate_sql: str
    parameters: tuple[TypedParameter, ...] = ()


@dataclass(frozen=True)
class Weakening:
    """Explicit existential-witness/conjunct deletion; None retains all."""

    keep_relations: tuple[str, ...] | None = None
    keep_predicates: tuple[str, ...] | None = None


def _node_payload(node: Any) -> Any:
    """Preserve exact node kinds in exported typed structure identities."""
    if node is None or type(node) in {str, int, bool}:
        return node
    if type(node) is tuple:
        return [_node_payload(child) for child in node]
    allowed = {
        ColumnType, ProtectedInput, OrdinaryRelation, Column, Literal, Parameter,
        TypedParameter, Arithmetic, Compare, Between, Conjunct, InnerJoin,
        Aggregate, Year, OutputName, SelectItem, OrderKey, ContinuationQuery,
    }
    if type(node) not in allowed:
        _fail("unsupported node in typed structure identity")
    return {"node": type(node).__name__, **{
        item.name: _node_payload(getattr(node, item.name)) for item in fields(node)
    }}


def _literal(kind: str, value: Any, *, contextual: bool = False) -> str:
    if type(kind) is not str or kind not in _KINDS:
        _fail("unsupported builtin literal type")
    if value is None:
        return "NULL::" + kind
    if kind in {"bigint", "integer"}:
        bound = 2 ** (63 if kind == "bigint" else 31)
        if type(value) is not int or not -bound <= value < bound:
            _fail("integer literal is outside its builtin type")
        # Bare decimal constants infer int4 first, then int8/numeric.  Preserve
        # a declared int8 (including its negative minimum) explicitly.
        if kind == "bigint" or value == -(2 ** 31):
            return "(" + str(value) + ")::" + kind
        return str(value)
    if kind == "boolean":
        if type(value) is not bool:
            _fail("boolean literal must be an exact boolean")
        return "TRUE" if value else "FALSE"
    if type(value) is not str:
        _fail("text/date/numeric literals require exact strings")
    if kind == "numeric":
        if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value) is None:
            _fail("unsupported numeric literal")
        return "(" + value + ")::numeric"
    if kind == "date":
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
            _fail("date literal must use ISO calendar syntax")
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise NecessityError("invalid calendar date") from exc
        return "DATE '" + value + "'"
    if "\x00" in value or "\\" in value:
        _fail("text literal contains unsupported bytes or escape syntax")
    rendered = "'" + value.replace("'", "''") + "'"
    # In qualifications the supported comparison supplies the known text
    # context.  Standalone/result arguments retain text explicitly.
    return rendered if contextual else rendered + "::text"


def _parameters(parameters: tuple[TypedParameter, ...]) -> dict[str, TypedParameter]:
    _tuple(parameters, TypedParameter, "parameters")
    result: dict[str, TypedParameter] = {}
    for param in parameters:
        _ident(param.name)
        _literal(param.type_name, param.value)
        if param.name in result:
            _fail("duplicate parameter identity")
        result[param.name] = param
    return result


def _schema(query: ContinuationQuery) -> dict[str, dict[str, ColumnType]]:
    if type(query) is not ContinuationQuery or type(query.protected) is not ProtectedInput:
        _fail("exact finite continuation/protected nodes are required")
    protected = query.protected
    _ident(protected.rid_column)
    _tuple(query.joins, InnerJoin, "inner joins", empty=False)
    relations: list[Any] = [protected]
    for join in query.joins:
        if type(join.relation) is not OrdinaryRelation:
            _fail("ordinary input must be a finite base relation")
        _ident(join.relation.name)
        if join.relation.schema != "public":
            _fail("only explicit public ordinary relations are supported")
        if type(join.relation.alias_with_as) is not bool:
            _fail("relation alias syntax must be an exact finite choice")
        relations.append(join.relation)
    result: dict[str, dict[str, ColumnType]] = {}
    for relation in relations:
        _ident(relation.alias)
        if relation.alias in result:
            _fail("duplicate relation alias")
        _tuple(relation.columns, ColumnType, "column schema", empty=False)
        cols: dict[str, ColumnType] = {}
        for col in relation.columns:
            _ident(col.name)
            if type(col.type_name) is not str or col.type_name not in _KINDS:
                _fail("column type is outside the builtin finite schema")
            if type(col.typmod) is not int:
                _fail("builtin column typmod must be an exact integer")
            if col.typmod != -1:
                # PostgreSQL REL_16_STABLE numeric.c make_numeric_typmod:
                # https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/numeric.c
                # Precision in high 16
                # bits, signed scale in low 11 bits, plus VARHDRSZ=4.
                encoded = col.typmod - 4
                precision = (encoded >> 16) & 0xffff
                scale = ((encoded & 0x7ff) ^ 1024) - 1024
                if (col.type_name != "numeric" or encoded < 0
                    or not 1 <= precision <= 1000 or not -1000 <= scale <= 1000
                    or encoded != ((precision << 16) | (scale & 0x7ff))):
                    _fail("unsupported or malformed builtin numeric typmod")
            if col.type_name == "text":
                if type(col.collation) is not str or col.collation not in {
                    "pg_catalog.default", "pg_catalog.C", "pg_catalog.POSIX"
                }:
                    _fail("text columns require an explicit finite builtin collation")
            elif col.collation is not None:
                _fail("noncollatable builtin columns cannot carry a collation")
            if col.name in cols:
                _fail("duplicate column identity")
            cols[col.name] = col
        result[relation.alias] = cols
    rid = result[protected.alias].get(protected.rid_column)
    if rid is None or rid.type_name not in {"bigint", "integer"}:
        _fail("protected RID must be a declared builtin integer column")
    return result


def _scalar(node: Any, schema: Mapping, params: Mapping, parent_prec: int = 0, *, contextual: bool = False) -> tuple[str, str, frozenset[str]]:
    if type(node) is Column:
        _ident(node.alias); _ident(node.name)
        column = schema.get(node.alias, {}).get(node.name)
        if column is None:
            _fail("column is absent from the finite schema")
        return node.alias + "." + node.name, column.type_name, frozenset({node.alias})
    if type(node) is Literal:
        return _literal(node.type_name, node.value, contextual=contextual), node.type_name, frozenset()
    if type(node) is Parameter:
        _ident(node.name)
        if node.name not in params:
            _fail("parameter is not bound")
        param = params[node.name]
        return _literal(param.type_name, param.value, contextual=contextual), param.type_name, frozenset()
    if type(node) is Arithmetic:
        if type(node.op) is not str or node.op not in {"+", "-", "*"}:
            _fail("unsupported arithmetic operator")
        prec = 20 if node.op == "*" else 10
        left, lkind, lrefs = _scalar(node.left, schema, params, prec)
        right, rkind, rrefs = _scalar(node.right, schema, params, prec + 1)
        if lkind not in _NUMERIC or rkind not in _NUMERIC:
            _fail("arithmetic requires builtin numeric values")
        sql = left + " " + node.op + " " + right
        if prec < parent_prec:
            sql = "(" + sql + ")"
        kind = "numeric" if "numeric" in {lkind, rkind} else ("bigint" if "bigint" in {lkind, rkind} else "integer")
        return sql, kind, lrefs | rrefs
    if type(node) is Year:
        value, kind, refs = _scalar(node.value, schema, params)
        if kind != "date":
            _fail("year extraction requires a date")
        return "date_part('year', " + value + ")::int", "integer", refs
    _fail("raw/unknown/function expressions are outside the finite scalar grammar")


def _compatible(left: str, right: str) -> bool:
    return left == right or left in _NUMERIC and right in _NUMERIC


def _predicate(node: Any, schema: Mapping, params: Mapping) -> tuple[str, frozenset[str]]:
    # Arithmetic is permitted in final result expressions, but not in reducers:
    # integer overflow/other partial builtin behavior needs its own proof.
    def operand(value: Any) -> tuple[str, str, frozenset[str]]:
        if type(value) not in {Column, Literal, Parameter}:
            _fail("reducer operands must be columns or typed scalar values")
        return _scalar(value, schema, params, contextual=True)
    operands = (node.left, node.right) if type(node) is Compare else (
        (node.value, node.lower, node.upper) if type(node) is Between else ()
    )
    collations = {
        schema[value.alias][value.name].collation
        for value in operands
        if type(value) is Column and value.alias in schema and value.name in schema[value.alias]
        and schema[value.alias][value.name].type_name == "text"
    }
    if len(collations) > 1:
        _fail("cross-collation text comparisons require unsupported resolution evidence")
    if type(node) is Compare:
        if type(node.op) is not str or node.op not in {"=", "<>", "<", "<=", ">", ">="}:
            _fail("unsupported comparison operator")
        left, lkind, lrefs = operand(node.left)
        right, rkind, rrefs = operand(node.right)
        if not _compatible(lkind, rkind):
            _fail("comparison has incompatible builtin types")
        return left + " " + node.op + " " + right, lrefs | rrefs
    if type(node) is Between:
        value, kind, refs = operand(node.value)
        lower, lkind, lrefs = operand(node.lower)
        upper, ukind, urefs = operand(node.upper)
        if not _compatible(kind, lkind) or not _compatible(kind, ukind):
            _fail("BETWEEN has incompatible builtin types")
        return value + " BETWEEN " + lower + " AND " + upper, refs | lrefs | urefs
    _fail("qualifications must be finite comparison/BETWEEN nodes")


def _conjuncts(query: ContinuationQuery, schema: Mapping, params: Mapping) -> tuple[tuple[Conjunct, str, frozenset[str]], ...]:
    rows: list[tuple[Conjunct, str, frozenset[str]]] = []
    seen: set[str] = set()
    available = {query.protected.alias}
    for join in query.joins:
        _tuple(join.on, Conjunct, "join predicates", empty=False)
        alias = join.relation.alias
        connected = False
        for conjunct in join.on:
            sql, refs = _predicate(conjunct.predicate, schema, params)
            if not refs <= available | {alias}:
                _fail("forward/external correlation in join predicate")
            pred = conjunct.predicate
            if type(pred) is Compare and pred.op == "=" and type(pred.left) is Column and type(pred.right) is Column:
                aliases = {pred.left.alias, pred.right.alias}
                connected |= alias in aliases and bool(aliases & available)
                for col in (pred.left, pred.right):
                    if col.alias == query.protected.alias and col.name != query.protected.rid_column:
                        _fail("protected/ordinary joins must correlate through the bound RID")
            elif len(refs) > 1:
                _fail("multi-relation qualifications require supported equality joins")
            rows.append((conjunct, sql, refs))
        if not connected:
            _fail("each ordinary witness requires a connected equality join")
        available.add(alias)
    _tuple(query.where, Conjunct, "WHERE predicates")
    for conjunct in query.where:
        sql, refs = _predicate(conjunct.predicate, schema, params)
        if len(refs) > 1:
            _fail("WHERE supports side-local conjuncts; joins belong in ON")
        rows.append((conjunct, sql, refs))
    for conjunct, _, _ in rows:
        _text(conjunct.predicate_id, "predicate ID")
        if conjunct.predicate_id in seen:
            _fail("duplicate predicate ID")
        seen.add(conjunct.predicate_id)
    return tuple(rows)


def render_continuation(query: ContinuationQuery, parameters: tuple[TypedParameter, ...] = ()) -> str:
    """Render the complete finite structure; no caller-supplied SQL hole."""
    schema = _schema(query)
    params = _parameters(parameters)
    _conjuncts(query, schema, params)
    _tuple(query.select, SelectItem, "SELECT items", empty=False)
    output_names: set[str] = set()

    def result_expr(node: Any) -> str:
        if type(node) is Aggregate:
            if type(node.name) is not str or node.name not in {"count", "sum"}:
                _fail("unsupported aggregate")
            if node.argument is None:
                if node.name != "count":
                    _fail("only count may have a star argument")
                arg = "*"
            else:
                arg, kind, _ = _scalar(node.argument, schema, params)
                if node.name == "sum" and kind not in _NUMERIC:
                    _fail("SUM requires numeric input")
            sql = node.name + "(" + arg + ")"
            if node.filter is not None:
                condition, _ = _predicate(node.filter, schema, params)
                sql += " FILTER (WHERE " + condition + ")"
            return sql
        return _scalar(node, schema, params)[0]

    selected: list[str] = []
    for item in query.select:
        sql = result_expr(item.expression)
        if item.alias is not None:
            _ident(item.alias)
            if item.alias in output_names:
                _fail("duplicate output alias")
            output_names.add(item.alias)
            sql += " AS " + item.alias
        selected.append(sql)

    def order_expr(node: Any) -> str:
        if type(node) is OutputName:
            _ident(node.name)
            if node.name not in output_names:
                _fail("unknown result alias")
            return node.name
        return _scalar(node, schema, params)[0]

    sql = "SELECT " + ", ".join(selected)
    sql += " FROM caprls_access_root AS " + query.protected.alias
    for join in query.joins:
        relation = join.relation
        sql += " JOIN public." + relation.name + (" AS " if relation.alias_with_as else " ") + relation.alias + " ON "
        sql += " AND ".join(_predicate(item.predicate, schema, params)[0] for item in join.on)
    if query.where:
        sql += " WHERE " + " AND ".join(_predicate(item.predicate, schema, params)[0] for item in query.where)
    if type(query.group_by) is not tuple:
        _fail("GROUP BY must be an immutable finite tuple")
    if query.group_by:
        sql += " GROUP BY " + ", ".join(order_expr(item) for item in query.group_by)
    _tuple(query.order_by, OrderKey, "ORDER BY")
    if query.order_by:
        for item in query.order_by:
            if type(item.descending) is not bool:
                _fail("order direction must be exact bool")
        sql += " ORDER BY " + ", ".join(order_expr(item.expression) + (" DESC" if item.descending else "") for item in query.order_by)
    if query.limit is not None:
        if type(query.limit) is not int or query.limit <= 0:
            _fail("only positive top-level result LIMIT is supported")
        sql += " LIMIT " + str(query.limit)
    return sql


@dataclass(frozen=True)
class BoundNecessitySource:
    """Local capability for one registered, exact-SQL continuation binding."""

    spec: Any = field(repr=False)
    query: ContinuationQuery
    bindings: NecessityBindings
    _construction_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _SOURCE_TOKEN:
            _fail("necessity source must be bound from a registered continuation")


@dataclass(frozen=True)
class NecessityEvidence:
    """Locally replayed proof capability; to_dict() exports detached data."""

    _report_json: str = field(repr=False)
    _construction_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _EVIDENCE_TOKEN:
            _fail("necessity evidence must be derived or replayed")

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._report_json)

    @property
    def predicate_sql(self) -> str:
        return require_necessity_evidence(self)["predicate_sql"]


_SOURCES: dict[int, tuple[weakref.ReferenceType, str]] = {}
_EVIDENCE: dict[int, tuple[weakref.ReferenceType, str, weakref.ReferenceType]] = {}


def _registered_spec_payload(spec: Any) -> dict[str, Any]:
    # Local import keeps a future core/contracts consumer out of the
    # root_selection -> strict_planning -> core import cycle.
    from .root_selection import ContinuationSpec, _require_registered_continuation_spec
    if type(spec) is not ContinuationSpec:
        _fail("necessity requires an exact source-controlled ContinuationSpec")
    try:
        digest = _require_registered_continuation_spec(spec)
    except (TypeError, ValueError) as exc:
        raise NecessityError("continuation source is detached or changed") from exc
    return {
        "spec_digest": digest,
        "continuation_sql_digest": spec.continuation_sql_digest,
        "exact_sql_digest": _hash({"exact_sql": spec.continuation_sql}),
        "spec_id": spec.spec_id,
        "query_id": spec.query_id,
        "policy_id": spec.policy_id,
        "renderer_id": spec.renderer_id,
        "renderer_version": spec.renderer_version,
    }


def _source_payload(spec: Any, query: ContinuationQuery, binding: NecessityBindings) -> dict[str, Any]:
    registered = _registered_spec_payload(spec)
    if type(binding) is not NecessityBindings or type(binding.target) is not PolicyAccessTarget:
        _fail("exact typed necessity/target bindings are required")
    for name in ("relation", "policy_id", "occurrence_id", "principal_id", "context_digest", "policy_predicate_digest"):
        _text(getattr(binding.target, name), "target " + name)
    binding.target.__post_init__()
    _ident(binding.rid_column)
    _text(binding.snapshot_id, "snapshot ID")
    if type(binding.gamma_snapshot_digest) is not str or _DIGEST.fullmatch(binding.gamma_snapshot_digest) is None:
        _fail("Gamma snapshot identity must be a sha256 digest")
    _text(binding.q_predicate_sql, "q predicate")
    if binding.target.policy_id != spec.policy_id:
        _fail("continuation policy and logical target differ")
    rendered = render_continuation(query, binding.parameters)
    if binding.rid_column != query.protected.rid_column:
        _fail("protected RID binding differs from continuation structure")
    if _sql_tokens(rendered) != _sql_tokens(spec.continuation_sql):
        _fail("typed continuation structure differs from the actual registered SQL")
    # All values have passed exact-node/scalar validation before serialization.
    structure = _node_payload(query)
    return {
        "source": registered,
        "structure": structure,
        "structure_digest": _hash(structure),
        "bindings": {
            "target": binding.target.to_dict(),
            "target_digest": binding.target.digest,
            "occurrence_id": binding.target.occurrence_id,
            "rid_column": binding.rid_column,
            "rid_domain": binding.target.relation + "." + binding.rid_column,
            "context_digest": binding.target.context_digest,
            "snapshot_id": binding.snapshot_id,
            "gamma_snapshot_digest": binding.gamma_snapshot_digest,
            "q_predicate_sql": binding.q_predicate_sql,
            "q_predicate_digest": canonical_predicate_digest(binding.q_predicate_sql),
            "parameters": [asdict(param) for param in binding.parameters],
            "parameters_digest": _hash([asdict(param) for param in binding.parameters]),
        },
        "result_phase_contract": "all_result_expressions_require_exact_authorized_input; finite_builtin_result_grammar_only",
    }


def bind_continuation_source(spec: Any, query: ContinuationQuery, bindings: NecessityBindings) -> BoundNecessitySource:
    """Check the full rendered SQL against a live registered source capability.

    Column schemas are explicit theorem assumptions, not catalog attestations.
    No unregistered JSON/source-shaped dataclass can mint this capability.
    """
    payload = _source_payload(spec, query, bindings)
    source = BoundNecessitySource(spec, query, bindings, _SOURCE_TOKEN)
    key = id(source)

    def drop(reference: weakref.ReferenceType) -> None:
        old = _SOURCES.get(key)
        if old is not None and old[0] is reference:
            _SOURCES.pop(key, None)

    _SOURCES[key] = (weakref.ref(source, drop), _hash(payload))
    return source


def _require_source(source: BoundNecessitySource) -> dict[str, Any]:
    if type(source) is not BoundNecessitySource or source._construction_token is not _SOURCE_TOKEN:
        _fail("necessity source lacks local provenance")
    registered = _SOURCES.get(id(source))
    if registered is None or registered[0]() is not source:
        _fail("necessity source is not locally registered")
    payload = _source_payload(source.spec, source.query, source.bindings)
    if registered[1] != _hash(payload):
        _fail("necessity source changed after binding")
    return payload


def _selection(value: tuple[str, ...] | None, universe: tuple[str, ...], label: str) -> tuple[str, ...]:
    if value is None:
        return universe
    if type(value) is not tuple or any(type(item) is not str for item in value):
        _fail(label + " must be an immutable tuple of IDs")
    if len(set(value)) != len(value) or not set(value) <= set(universe):
        _fail(label + " contains duplicate or unknown identities")
    # Canonical source order gives replay a single derivation spelling.
    return tuple(item for item in universe if item in value)


def _derive_report(source: BoundNecessitySource, weakening: Weakening) -> dict[str, Any]:
    payload = _require_source(source)
    if type(weakening) is not Weakening:
        _fail("weakening must be an exact rule-selection node")
    query = source.query
    schema = _schema(query)
    params = _parameters(source.bindings.parameters)
    conjuncts = _conjuncts(query, schema, params)
    aliases = tuple(join.relation.alias for join in query.joins)
    kept = _selection(weakening.keep_relations, aliases, "ordinary witness selection")
    if not kept:
        _fail("necessity must retain a meaningful ordinary witness")
    available = frozenset(kept) | {query.protected.alias}
    eligible = tuple(item.predicate_id for item, _, refs in conjuncts if refs <= available)
    # Removing an existential witness necessarily removes its incident atoms.
    selected = _selection(weakening.keep_predicates, eligible, "conjunct selection")
    selected_set = set(selected)
    retained = [(item, sql, refs) for item, sql, refs in conjuncts if item.predicate_id in selected_set]

    adjacency = {alias: set() for alias in available}
    for item, _, _ in retained:
        pred = item.predicate
        if type(pred) is Compare and pred.op == "=" and type(pred.left) is Column and type(pred.right) is Column:
            left, right = pred.left.alias, pred.right.alias
            if left != right:
                adjacency[left].add(right); adjacency[right].add(left)
    reachable = {query.protected.alias}
    pending = [query.protected.alias]
    while pending:
        for alias in adjacency[pending.pop()] - reachable:
            reachable.add(alias); pending.append(alias)
    if reachable != set(available):
        _fail("retained ordinary witnesses must remain connected to the protected RID")

    relations = tuple(join.relation for join in query.joins if join.relation.alias in kept)
    predicate = "EXISTS (SELECT 1 FROM "
    predicate += ", ".join("public." + rel.name + " AS " + rel.alias for rel in relations)
    predicate += " WHERE " + " AND ".join("(" + sql + ")" for _, sql, _ in retained) + ")"
    protected_columns: set[str] = set()

    def collect_columns(node: Any) -> None:
        if type(node) is Column:
            if node.alias == query.protected.alias:
                protected_columns.add(node.name)
        elif type(node) in {Compare, Between}:
            for value in vars(node).values():
                if type(value) is Column:
                    collect_columns(value)
    for item, _, _ in retained:
        collect_columns(item.predicate)
    predicates = []
    for item, sql, refs in conjuncts:
        predicates.append({
            "predicate_id": item.predicate_id,
            "sql": sql,
            "sql_digest": canonical_predicate_digest(sql),
            "referenced_aliases": sorted(refs),
            "rule": "retain_conjunct" if item.predicate_id in selected_set else (
                "drop_atom_with_removed_witness" if not refs <= available else "drop_conjunct"
            ),
        })
    return {
        "schema": "caprls_continuation_necessity_v1",
        "theorem": "for_every_input_subbag_join_bag_X_equals_join_bag_filter_D_X",
        "proof_state": "detached_report_requires_current_source_and_replay",
        "source_binding": payload,
        "ordinary_witness_rules": [
            {"alias": alias, "rule": "retain_existential_witness" if alias in kept else "drop_existential_witness"}
            for alias in aliases
        ],
        "predicate_rules": predicates,
        "kept_relations": list(kept),
        "kept_predicates": list(selected),
        "predicate_sql": predicate,
        "predicate_digest": canonical_predicate_digest(predicate),
        "required_protected_columns": sorted(protected_columns),
        "required_schema_assumptions": {
            relation.alias: {
                "relation": "caprls_access_root" if type(relation) is ProtectedInput else "public." + relation.name,
                "role": "protected_input" if type(relation) is ProtectedInput else "ordinary_witness",
                "columns": [
                    {"name": col.name, "type_namespace": "pg_catalog", "type_name": col.type_name,
                     "typmod": col.typmod, "collation": col.collation}
                    for col in relation.columns
                ],
            }
            for relation in (query.protected, *(join.relation for join in query.joins))
        },
        "assumption_scope": "recorded_builtin_schema_and_safe_ordinary_reads_require_adapter_validation; no_Gamma_or_runtime_authorization_issued",
        "required_resolution_assumptions": "actual_operators_casts_and_result_builtins_resolve_to_pg_catalog_implementations_under_bound_session; no_implicit_user_cast_or_function",
        "bag_rule": "EXISTS_preserves_every_retained_input_multiplicity",
        "null_rule": "only_SQL_TRUE_is_an_existential_witness",
        "post_result_scope": "same_joined_bag_and_fixed_post_operators; existing_result_order_and_tie_contract_still_required",
    }


def _mint_evidence(source: BoundNecessitySource, report: dict[str, Any]) -> NecessityEvidence:
    evidence = NecessityEvidence(_json(report), _EVIDENCE_TOKEN)
    key = id(evidence)

    def drop(reference: weakref.ReferenceType) -> None:
        old = _EVIDENCE.get(key)
        if old is not None and old[0] is reference:
            _EVIDENCE.pop(key, None)

    _EVIDENCE[key] = (weakref.ref(evidence, drop), _hash(report), weakref.ref(source))
    return evidence


def derive_continuation_necessity(source: BoundNecessitySource, weakening: Weakening = Weakening()) -> NecessityEvidence:
    """Apply checked witness/conjunct deletion rules to the actual structure."""
    return _mint_evidence(source, _derive_report(source, weakening))


def replay_continuation_necessity(source: BoundNecessitySource, report: Mapping[str, Any]) -> NecessityEvidence:
    """Recompute all proof content under a current source, then mint evidence.

    JSON supplies the proposed rule IDs, never a necessity/safety assertion.
    Matching a digest alone is insufficient: the whole derivation is rebuilt.
    """
    _require_source(source)
    if type(report) is not dict:
        _fail("replay requires a detached exact JSON object")
    relations = report.get("kept_relations")
    predicates = report.get("kept_predicates")
    if type(relations) is not list or type(predicates) is not list:
        _fail("proof lacks explicit witness/conjunct rule selections")
    weakening = Weakening(tuple(relations), tuple(predicates))
    expected = _derive_report(source, weakening)
    try:
        matches = _json(report) == _json(expected)
    except (TypeError, ValueError) as exc:
        raise NecessityError("proof is not finite JSON data") from exc
    if not matches:
        _fail("necessity report differs from the replayed derivation/bindings")
    return _mint_evidence(source, expected)


def require_necessity_evidence(evidence: NecessityEvidence, source: BoundNecessitySource | None = None) -> dict[str, Any]:
    """Accept only a live locally derived/replayed capability, never JSON."""
    if type(evidence) is not NecessityEvidence or evidence._construction_token is not _EVIDENCE_TOKEN:
        _fail("detached necessity data is not proof provenance")
    if type(evidence._report_json) is not str:
        _fail("necessity evidence report identity is malformed")
    registered = _EVIDENCE.get(id(evidence))
    if registered is None or registered[0]() is not evidence:
        _fail("necessity evidence is not locally registered")
    origin = registered[2]()
    if origin is None or source is not None and source is not origin:
        _fail("necessity evidence belongs to another or expired source")
    try:
        report = json.loads(evidence._report_json)
    except (TypeError, ValueError) as exc:
        raise NecessityError("necessity evidence report identity is malformed") from exc
    if registered[1] != _hash(report):
        _fail("necessity evidence changed after replay")
    expected = _derive_report(origin, Weakening(tuple(report["kept_relations"]), tuple(report["kept_predicates"])))
    if _json(expected) != _json(report):
        _fail("necessity evidence has stale source bindings")
    return report
