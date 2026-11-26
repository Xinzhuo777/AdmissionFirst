SELECT t.studio_id, count(*) AS title_company_edges
  FROM public.job_title AS t
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year >= 1980
    AND mc.company_type = 'production'
  GROUP BY t.studio_id
  ORDER BY title_company_edges DESC, t.studio_id
  LIMIT 20;