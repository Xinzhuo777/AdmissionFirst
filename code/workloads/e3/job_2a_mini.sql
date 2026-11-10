-- E3-MINI+ JOB/IMDb 2a-style adapter.
-- Authorization is discharged on title before company aggregation.
SELECT t.production_year, count(*) AS production_edges
FROM public.job_title AS t
JOIN public.job_movie_companies AS mc ON mc.movie_id = t.t_id
WHERE t.kind = :kind
  AND t.production_year BETWEEN :year_lo AND :year_hi
  AND mc.company_type = :company_type
GROUP BY t.production_year
ORDER BY production_edges DESC, t.production_year
LIMIT 20;
