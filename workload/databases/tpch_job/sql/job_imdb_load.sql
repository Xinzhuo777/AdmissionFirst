-- Join Order Benchmark (IMDb) subset: title, movie_companies and cast_info,
-- reduced to the columns used by the queries and row policies.  kind and
-- company_type come from the real kind_type / company_type dimensions;
-- region_id and studio_id are synthetic policy attributes derived from the
-- title key.  NULL production years become 0 (the queries' year filters
-- exclude them).
--
-- Run exactly as written (one psql session, autocommit); see tpch_load.sql.
-- The IMDb CSV snapshot escapes embedded quotes with a backslash, hence
-- ESCAPE '\'.  The data directory placeholder is filled in by the build script.

CREATE TABLE public.job_title (
  t_id bigint PRIMARY KEY,
  kind text NOT NULL,
  production_year integer NOT NULL,
  region_id bigint NOT NULL,
  studio_id bigint NOT NULL
);
CREATE TABLE public.job_movie_companies (
  movie_id bigint NOT NULL,
  company_id bigint NOT NULL,
  company_type text NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.job_cast_info (
  movie_id bigint NOT NULL,
  person_id bigint NOT NULL,
  role_id bigint NOT NULL
);
CREATE UNLOGGED TABLE public.stg_kind_type (id int, kind text);
CREATE UNLOGGED TABLE public.stg_company_type (id int, kind text);
CREATE UNLOGGED TABLE public.stg_title (
  id bigint, title text, imdb_index text, kind_id int, production_year int,
  imdb_id int, phonetic_code text, episode_of_id int, season_nr int,
  episode_nr int, series_years text, md5sum text
);
CREATE UNLOGGED TABLE public.stg_movie_companies (
  id bigint, movie_id bigint, company_id bigint, company_type_id int, note text
);
CREATE UNLOGGED TABLE public.stg_cast_info (
  id bigint, person_id bigint, movie_id bigint, person_role_id int, note text,
  nr_order int, role_id int
);
COPY public.stg_kind_type FROM '@IMDB_DIR@/kind_type.csv' WITH (FORMAT csv, ESCAPE '\');
COPY public.stg_company_type FROM '@IMDB_DIR@/company_type.csv' WITH (FORMAT csv, ESCAPE '\');
COPY public.stg_title FROM '@IMDB_DIR@/title.csv' WITH (FORMAT csv, ESCAPE '\');
COPY public.stg_movie_companies FROM '@IMDB_DIR@/movie_companies.csv' WITH (FORMAT csv, ESCAPE '\');
COPY public.stg_cast_info FROM '@IMDB_DIR@/cast_info.csv' WITH (FORMAT csv, ESCAPE '\');
-- job_title row order is the output order of the plan the original load
-- used: a merge join whose stg_title side is an external sort on kind_id
-- with work_mem = 16MB (the planner picks it on its own because the staging
-- tables have no statistics).  Rows come out grouped by kind_id; inside each
-- kind the order is what PostgreSQL 16's tuplesort produces for these input
-- rows and this memory budget, which is deterministic.  The settings below
-- pin that plan and memory budget independently of server configuration;
-- a different work_mem gives a different (equally valid) row order.
SET work_mem = '16MB';
SET enable_hashjoin = off;
SET enable_nestloop = off;
INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id)
SELECT t.id, k.kind, COALESCE(t.production_year, 0), 1 + (t.id % 5), 1 + (t.id % 50)
FROM public.stg_title t
JOIN public.stg_kind_type k ON k.id = t.kind_id;
RESET enable_nestloop;
RESET enable_hashjoin;
RESET work_mem;
INSERT INTO public.job_movie_companies(movie_id, company_id, company_type, region_id)
SELECT m.movie_id, m.company_id,
       CASE WHEN c.kind = 'production companies' THEN 'production' ELSE 'distributor' END,
       1 + (m.movie_id % 5)
FROM public.stg_movie_companies m
JOIN public.stg_company_type c ON c.id = m.company_type_id
ORDER BY m.ctid;
INSERT INTO public.job_cast_info(movie_id, person_id, role_id)
SELECT movie_id, person_id, role_id FROM public.stg_cast_info;
DROP TABLE public.stg_cast_info;
DROP TABLE public.stg_movie_companies;
DROP TABLE public.stg_title;
DROP TABLE public.stg_company_type;
DROP TABLE public.stg_kind_type;
CREATE INDEX job_title_kind_year_idx ON public.job_title(kind, production_year, t_id);
CREATE INDEX job_title_region_idx ON public.job_title(region_id, t_id);
CREATE INDEX job_movie_companies_movie_type_idx ON public.job_movie_companies(movie_id, company_type);
CREATE INDEX job_cast_info_movie_role_idx ON public.job_cast_info(movie_id, role_id);
ANALYZE public.job_title;
ANALYZE public.job_movie_companies;
ANALYZE public.job_cast_info;
