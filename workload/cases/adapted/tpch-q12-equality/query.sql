SELECT
    o.o_shippriority,
    count(*) FILTER (WHERE l.l_shipdate < DATE '1995-01-01') AS early_ship_count,
    count(*) FILTER (WHERE l.l_shipdate >= DATE '1995-01-01') AS late_ship_count
  FROM public.tpch_customer AS c
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1994-01-01'
    AND o.o_orderdate < DATE '1995-01-01'
  GROUP BY o.o_shippriority
  ORDER BY o.o_shippriority;