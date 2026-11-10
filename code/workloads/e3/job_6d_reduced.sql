-- E3 reduced JOB/IMDB 6d-style adapter.
-- The runner creates deterministic public.job_* tables and discharges
-- authorization on title before join/aggregate/order/limit.
SELECT t.studio_id, count(*) AS cast_edges
FROM public.job_title AS t
JOIN public.job_cast_info AS ci ON ci.movie_id = t.t_id
WHERE t.kind = :kind
  AND t.production_year >= :year_lo
  AND ci.role_id <= :max_role
GROUP BY t.studio_id
ORDER BY cast_edges DESC, t.studio_id
LIMIT 20;
