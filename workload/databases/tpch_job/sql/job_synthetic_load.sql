-- Small synthetic stand-in for the JOB tables, used in the TPC-H SF10
-- database (the SF10 workload only queries the TPC-H tables, but the row
-- policy tables must exist).  Same table shapes as job_imdb_load.sql, with
-- foreign keys, populated from generate_series.  No input files.

CREATE TABLE public.job_title (
  t_id bigint PRIMARY KEY,
  kind text NOT NULL,
  production_year integer NOT NULL,
  region_id bigint NOT NULL,
  studio_id bigint NOT NULL
);
CREATE TABLE public.job_movie_companies (
  movie_id bigint NOT NULL REFERENCES public.job_title(t_id),
  company_id bigint NOT NULL,
  company_type text NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.job_cast_info (
  movie_id bigint NOT NULL REFERENCES public.job_title(t_id),
  person_id bigint NOT NULL,
  role_id bigint NOT NULL
);
INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id)
SELECT t,
       CASE WHEN t % 2 = 0 THEN 'movie' ELSE 'episode' END,
       1980 + (t % 40),
       1 + (t % 5),
       1 + (t % 50)
FROM generate_series(1, 1500) AS t;
INSERT INTO public.job_movie_companies(movie_id, company_id, company_type, region_id)
SELECT 1 + (mc % 1500),
       1 + (mc % 300),
       CASE WHEN mc % 3 = 0 THEN 'production' ELSE 'distributor' END,
       1 + (mc % 5)
FROM generate_series(1, 4000) AS mc;
INSERT INTO public.job_cast_info(movie_id, person_id, role_id)
SELECT 1 + (ci % 1500),
       1 + (ci % 2000),
       1 + (ci % 8)
FROM generate_series(1, 8000) AS ci;
CREATE INDEX job_title_kind_year_idx ON public.job_title(kind, production_year, t_id);
CREATE INDEX job_title_region_idx ON public.job_title(region_id, t_id);
CREATE INDEX job_movie_companies_movie_type_idx ON public.job_movie_companies(movie_id, company_type);
CREATE INDEX job_cast_info_movie_role_idx ON public.job_cast_info(movie_id, role_id);
ANALYZE public.job_title;
ANALYZE public.job_movie_companies;
ANALYZE public.job_cast_info;
