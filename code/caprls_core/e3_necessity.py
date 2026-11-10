"""Finite typed structures for E3's actual source-controlled consumers.

Binding still compares the full rendered SQL against the registered source;
a matching query label alone is insufficient. These are schema assumptions,
checked independently by continuation_schema before production admission.
"""
from __future__ import annotations

from planner.continuation_necessity import (
    Aggregate, Arithmetic, Between, Column, ColumnType, Compare, Conjunct,
    ContinuationQuery, InnerJoin, Literal, NecessityBindings, NecessityError,
    OrderKey, OrdinaryRelation, OutputName, ProtectedInput, SelectItem, Year,
    bind_continuation_source,
)


def _columns(**kinds):
    return tuple(ColumnType(name, kind, "pg_catalog.default" if kind == "text" else None,
                            ((12 << 16) | 2) + 4 if name == "l_extendedprice" else
                            ((5 << 16) | 4) + 4 if name == "l_discount" else -1)
                 for name, kind in kinds.items())


def _atom(name, op, left, right):
    return Conjunct(name, Compare(op, left, right))


def _date(name, op, alias, column, value):
    return _atom(name, op, Column(alias, column), Literal("date", value))


def _tpch(query_id):
    c = ProtectedInput("c", "c_custkey", _columns(
        c_custkey="bigint", region_id="bigint", c_mktsegment="text"))
    o = OrdinaryRelation("tpch_orders", "o", _columns(
        o_custkey="bigint", o_orderkey="bigint", o_orderdate="date", o_shippriority="integer"))
    l = OrdinaryRelation("tpch_lineitem", "l", _columns(
        l_orderkey="bigint", l_shipdate="date", l_extendedprice="numeric", l_discount="numeric"))
    joins = (InnerJoin(o, (_atom("orders_customer", "=", Column("o", "o_custkey"), Column("c", "c_custkey")),)),
             InnerJoin(l, (_atom("lineitem_order", "=", Column("l", "l_orderkey"), Column("o", "o_orderkey")),)))
    where = ( _atom("segment", "=", Column("c", "c_mktsegment"), Literal("text", "BUILDING")), )
    revenue = SelectItem(Aggregate("sum", Arithmetic("*", Column("l", "l_extendedprice"),
        Arithmetic("-", Literal("integer", 1), Column("l", "l_discount")))), "revenue")
    if query_id == "Q3":
        where += (_date("order_end", "<", "o", "o_orderdate", "1995-03-15"),
                  _date("ship_start", ">", "l", "l_shipdate", "1995-03-15"))
        group = (Column("l", "l_orderkey"), Column("o", "o_orderdate"), Column("o", "o_shippriority"))
        select = (SelectItem(group[0]), revenue, SelectItem(group[1]), SelectItem(group[2]))
        order = (OrderKey(OutputName("revenue"), True), OrderKey(group[1])); limit = 10
    elif query_id in {"Q5", "Q7", "Q10", "Q12"}:
        start, end = {"Q5": ("1995-01-15", "1995-04-01"), "Q7": ("1994-01-01", "1997-01-01"),
                      "Q10": ("1993-10-01", "1994-01-01"), "Q12": ("1994-01-01", "1995-01-01")}[query_id]
        where += (_date("order_start", ">=", "o", "o_orderdate", start),
                  _date("order_end", "<", "o", "o_orderdate", end))
        if query_id != "Q12":
            ship = "1995-02-01" if query_id == "Q5" else start
            where += (_date("ship_start", ">" if query_id == "Q5" else ">=", "l", "l_shipdate", ship),)
        if query_id == "Q5":
            group = (Column("c", "region_id"),); select = (SelectItem(group[0]), revenue)
            order = (OrderKey(OutputName("revenue"), True),); limit = 10
        elif query_id == "Q7":
            where += (_date("ship_end", "<", "l", "l_shipdate", end),)
            group = (Column("c", "region_id"), OutputName("order_year"))
            select = (SelectItem(group[0]), SelectItem(Year(Column("o", "o_orderdate")), "order_year"), revenue)
            order = (OrderKey(OutputName("revenue"), True), OrderKey(group[0]), OrderKey(group[1])); limit = 20
        elif query_id == "Q10":
            group = (Column("c", "c_custkey"), Column("c", "region_id"))
            select = (SelectItem(group[0]), SelectItem(group[1]), revenue)
            order = (OrderKey(OutputName("revenue"), True), OrderKey(group[0])); limit = 20
        else:
            group = (Column("o", "o_shippriority"),)
            select = (SelectItem(group[0]), *(SelectItem(Aggregate("count", filter=Compare(op,
                Column("l", "l_shipdate"), Literal("date", "1995-01-01"))), name)
                for op, name in (("<", "early_ship_count"), (">=", "late_ship_count"))))
            order = (OrderKey(group[0]),); limit = None
    else:
        raise NecessityError("unsupported E3 TPC-H consumer")
    return ContinuationQuery(c, joins, where, select, group, order, limit)


def _job(query_id):
    if query_id not in {"JOB_1a", "JOB_2a", "JOB_3c", "JOB_6d", "JOB_16b"}:
        # JOB_10a has an IN qualification, outside the current finite grammar.
        raise NecessityError("E3 consumer is outside the finite continuation grammar")
    t = ProtectedInput("t", "t_id", _columns(t_id="bigint", kind="text", production_year="integer",
                                            region_id="bigint", studio_id="bigint"))
    mc = OrdinaryRelation("job_movie_companies", "mc", _columns(movie_id="bigint", company_type="text"), alias_with_as=False)
    ci = OrdinaryRelation("job_cast_info", "ci", _columns(movie_id="bigint", role_id="bigint"), alias_with_as=False)
    relations = ((ci,) if query_id == "JOB_6d" else
                 (mc, ci) if query_id in {"JOB_1a", "JOB_3c"} else (mc,))
    joins = tuple(InnerJoin(rel, (_atom(rel.alias + "_title", "=", Column(rel.alias, "movie_id"), Column("t", "t_id")),))
                  for rel in relations)
    where = (_atom("kind", "=", Column("t", "kind"), Literal("text", "movie")),)
    if query_id in {"JOB_1a", "JOB_2a", "JOB_3c"}:
        low, high = {"JOB_1a": (1990, 2010), "JOB_2a": (1985, 2015), "JOB_3c": (1980, 2005)}[query_id]
        where += (Conjunct("year", Between(Column("t", "production_year"), Literal("integer", low), Literal("integer", high))),)
    else:
        where += (_atom("year", ">=", Column("t", "production_year"), Literal("integer", 1995 if query_id == "JOB_6d" else 1980)),)
    if mc in relations:
        where += (_atom("company_type", "=", Column("mc", "company_type"), Literal("text", "distributor" if query_id == "JOB_3c" else "production")),)
    if query_id in {"JOB_3c", "JOB_6d"}:
        where += (_atom("role", "<=", Column("ci", "role_id"), Literal("integer", 4 if query_id == "JOB_3c" else 3)),)
    key, name = {"JOB_1a": ("t_id", "matches"), "JOB_2a": ("production_year", "production_edges"),
                 "JOB_3c": ("region_id", "regional_cast_edges"), "JOB_6d": ("studio_id", "cast_edges"),
                 "JOB_16b": ("studio_id", "title_company_edges")}[query_id]
    group = (Column("t", key),)
    return ContinuationQuery(t, joins, where, (SelectItem(group[0]), SelectItem(Aggregate("count"), name)),
                             group, (OrderKey(OutputName(name), True), OrderKey(group[0])), 20)


def bind_e3_necessity_source(query, policy, bindings: NecessityBindings):
    from . import e3_main as e3
    e3._require_e3_canonical_query_policy_sources(query, policy)
    if (bindings.target.relation != query.protected_rel
        or bindings.target.policy_id != policy.config_id
        or bindings.rid_column != query.rid_col
        or bindings.q_predicate_sql != e3._e3_query_predicate(query, query.alias)):
        raise NecessityError("E3 necessity target or local predicate differs from canonical source")
    structure = _tpch(query.query_id) if query.workload == "tpch" else _job(query.query_id)
    return bind_continuation_source(e3._e3_continuation_spec(query, policy), structure, bindings)
