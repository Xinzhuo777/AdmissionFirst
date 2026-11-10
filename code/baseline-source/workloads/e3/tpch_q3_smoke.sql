-- E3 TPC-H Q3 adapter smoke.
-- The runner creates tiny public.tpch_* tables and renders each mode's
-- authorization representation before this aggregate/order/limit boundary.
SELECT
  l.l_orderkey,
  sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
  o.o_orderdate,
  o.o_shippriority
FROM public.tpch_customer AS c
JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
WHERE c.c_mktsegment = :segment
  AND o.o_orderdate < :cutoff_date
  AND l.l_shipdate > :cutoff_date
GROUP BY l.l_orderkey, o.o_orderdate, o.o_shippriority
ORDER BY revenue DESC, o.o_orderdate
LIMIT 10;
