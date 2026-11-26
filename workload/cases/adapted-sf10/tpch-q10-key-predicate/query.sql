SELECT
    c.c_custkey,
    c.region_id,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM public.tpch_customer AS c
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1993-10-01'
    AND o.o_orderdate < DATE '1994-01-01'
    AND l.l_shipdate >= DATE '1993-10-01'
  GROUP BY c.c_custkey, c.region_id
  ORDER BY revenue DESC, c.c_custkey
  LIMIT 20;