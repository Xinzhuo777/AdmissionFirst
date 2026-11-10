-- E3 reduced JOB/IMDB 1a-style adapter.
-- The runner creates deterministic public.job_* tables and discharges
-- authorization on title before join/aggregate/order/limit.
SELECT t.t_id, count(*) AS matches
FROM public.job_title AS t
JOIN public.job_movie_companies AS mc ON mc.movie_id = t.t_id
JOIN public.job_cast_info AS ci ON ci.movie_id = t.t_id
WHERE t.kind = :kind
  AND t.production_year BETWEEN :year_lo AND :year_hi
  AND mc.company_type = :company_type
GROUP BY t.t_id
ORDER BY matches DESC, t.t_id
LIMIT 20;
