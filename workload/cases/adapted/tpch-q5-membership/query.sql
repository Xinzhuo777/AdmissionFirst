SELECT
    c.region_id,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM public.tpch_customer AS c
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1995-01-15'
    AND o.o_orderdate < DATE '1995-04-01'
    AND l.l_shipdate > DATE '1995-02-01'
  GROUP BY c.region_id
  ORDER BY revenue DESC
  LIMIT 10;