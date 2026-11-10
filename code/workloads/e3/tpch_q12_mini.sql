-- E3-MINI+ TPC-H Q12-style adapter.
-- Authorization is discharged on customer before shipping priority aggregation.
SELECT
  o.o_shippriority,
  count(*) FILTER (WHERE l.l_shipdate < :ship_cutoff) AS early_ship_count,
  count(*) FILTER (WHERE l.l_shipdate >= :ship_cutoff) AS late_ship_count
FROM public.tpch_customer AS c
JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
WHERE c.c_mktsegment = :segment
  AND o.o_orderdate >= :start_date
  AND o.o_orderdate < :end_date
GROUP BY o.o_shippriority
ORDER BY o.o_shippriority;
