SELECT
    c.region_id,
    date_part('year', o.o_orderdate)::int AS order_year,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM public.tpch_customer AS c
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1994-01-01'
    AND o.o_orderdate < DATE '1997-01-01'
    AND l.l_shipdate >= DATE '1994-01-01'
    AND l.l_shipdate < DATE '1997-01-01'
  GROUP BY c.region_id, order_year
  ORDER BY revenue DESC, c.region_id, order_year
  LIMIT 20;