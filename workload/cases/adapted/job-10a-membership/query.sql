SELECT t.production_year, count(*) AS company_edges
  FROM public.job_title AS t
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1990 AND 2020
    AND mc.company_type IN ('production', 'distributor')
  GROUP BY t.production_year
  ORDER BY company_edges DESC, t.production_year
  LIMIT 20;