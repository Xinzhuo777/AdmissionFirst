SELECT t.studio_id, count(*) AS cast_edges
  FROM public.job_title AS t
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year >= 1995
    AND ci.role_id <= 3
  GROUP BY t.studio_id
  ORDER BY cast_edges DESC, t.studio_id
  LIMIT 20;