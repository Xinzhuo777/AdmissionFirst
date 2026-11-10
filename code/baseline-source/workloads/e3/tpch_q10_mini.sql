-- E3-MINI+ TPC-H Q10-style adapter.
-- Authorization is discharged on customer before customer revenue ranking.
SELECT
  c.c_custkey,
  c.region_id,
  sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
FROM public.tpch_customer AS c
JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
WHERE c.c_mktsegment = :segment
  AND o.o_orderdate >= :start_date
  AND o.o_orderdate < :end_date
  AND l.l_shipdate >= :start_date
GROUP BY c.c_custkey, c.region_id
ORDER BY revenue DESC, c.c_custkey
LIMIT 20;
