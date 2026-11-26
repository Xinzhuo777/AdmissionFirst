SELECT t.production_year, count(*) AS production_edges
  FROM public.job_title AS t
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1985 AND 2015
    AND mc.company_type = 'production'
  GROUP BY t.production_year
  ORDER BY production_edges DESC, t.production_year
  LIMIT 20;