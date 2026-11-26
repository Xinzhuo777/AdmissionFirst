SELECT t.region_id, count(*) AS regional_cast_edges
  FROM public.job_title AS t
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1980 AND 2005
    AND mc.company_type = 'distributor'
    AND ci.role_id <= 4
  GROUP BY t.region_id
  ORDER BY regional_cast_edges DESC, t.region_id
  LIMIT 20;