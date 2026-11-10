-- E3-MINI+ JOB/IMDb 16b-style adapter.
-- Authorization is discharged on title before studio/company aggregation.
SELECT t.studio_id, count(*) AS title_company_edges
FROM public.job_title AS t
JOIN public.job_movie_companies AS mc ON mc.movie_id = t.t_id
WHERE t.kind = :kind
  AND t.production_year >= :year_lo
  AND mc.company_type = :company_type
GROUP BY t.studio_id
ORDER BY title_company_edges DESC, t.studio_id
LIMIT 20;
