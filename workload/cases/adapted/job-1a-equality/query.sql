SELECT t.t_id, count(*) AS matches
  FROM public.job_title AS t
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1990 AND 2010
    AND mc.company_type = 'production'
  GROUP BY t.t_id
  ORDER BY matches DESC, t.t_id
  LIMIT 20;