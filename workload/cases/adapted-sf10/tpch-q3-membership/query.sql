SELECT
    l.l_orderkey,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
    o.o_orderdate,
    o.o_shippriority
  FROM public.tpch_customer AS c
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate < DATE '1995-03-15'
    AND l.l_shipdate > DATE '1995-03-15'
  GROUP BY l.l_orderkey, o.o_orderdate, o.o_shippriority
  ORDER BY revenue DESC, o.o_orderdate
  LIMIT 10;