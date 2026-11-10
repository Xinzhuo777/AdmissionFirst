-- E3-MINI+ JOB/IMDb 3c-style adapter.
-- Authorization is discharged on title before company/cast aggregation.
SELECT t.region_id, count(*) AS regional_cast_edges
FROM public.job_title AS t
JOIN public.job_movie_companies AS mc ON mc.movie_id = t.t_id
JOIN public.job_cast_info AS ci ON ci.movie_id = t.t_id
WHERE t.kind = :kind
  AND t.production_year BETWEEN :year_lo AND :year_hi
  AND mc.company_type = :company_type
  AND ci.role_id <= :max_role
GROUP BY t.region_id
ORDER BY regional_cast_edges DESC, t.region_id
LIMIT 20;
