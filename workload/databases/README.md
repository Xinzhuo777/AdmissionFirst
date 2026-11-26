# Database build scripts

`build_all.sh` creates a new cluster and runs the scripts below in order (see
`../README.md` for the raw input files). Each script can also be run on its
own against a running PostgreSQL 16 server; run it with `--help` (or `-h`)
for its options.

| Directory / script | Databases | Inputs | Time on the test machine |
| --- | --- | --- | --- |
| `tpch_job/build.sh` | `tpch_job`, `tpch_sf10` | TPC-H SF1 and SF10, five IMDb tables | see below |
| `original_queries/build.sh` | `original_queries` | TPC-H SF1, all 21 IMDb tables | about 5 minutes |
| `searches/build_title_search.sh` | `title_search` | generated | under 10 seconds |
| `searches/build_path_search.sh` | `path_search` | generated | under 30 seconds |
| `application/build.sh` | `application` | generated | under 30 seconds |

Common requirements:

* Connect as the bootstrap superuser `postgres`; object owners appear in the
  recorded catalog state.
* Keep `autovacuum = off`, and do not run `VACUUM` or `ANALYZE` on the built
  databases. Both change visibility maps or planner statistics and therefore
  plans.
* Each target database must not exist yet.

What the scripts guarantee: every table has the same rows in the same
physical order (the same `ctid` for every row) as in the measured database,
with the same indexes, roles, grants, policies and database settings. The
data of the synthetic databases is generated deterministically. Because
`ANALYZE` samples rows at random, the scripts finally install the planner
statistics recorded from the measured databases (`stats/`, `sql/` or `data/`
in each directory). Each script ends by comparing checksums of the result
with those of the measured database and fails on any difference.
