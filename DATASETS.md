# Preparing benchmark inputs

The data and third-party generator are not included. These instructions describe
the file layout expected by the A018 code. Check the providers' terms before
downloading or using their data.

## TPC-H SF1 and SF10

Obtain the official [TPC-H 3.0.1 tools](https://www.tpc.org/tpc_documents_current_versions/download_programs/tools-download-request5.asp?bm_type=TPC-H&bm_vers=3.0.1&mode=CURRENT-ONLY),
accept the applicable terms and build DBGEN according to its instructions. Keep
the `dbgen` binary with its matching `dists.dss`. From the `code/` directory,
set `DBGEN_DIR` to that tools directory and generate into empty directories:

```sh
DBGEN_DIR=/absolute/path/to/official-tools/dbgen
ARTIFACT_ROOT="$(pwd)"
mkdir -p datasets/tpch/sf1 datasets/tpch/sf10
for sf in 1 10; do
  for table in c O L n; do
    DSS_CONFIG="$DBGEN_DIR" \
    DSS_PATH="$ARTIFACT_ROOT/datasets/tpch/sf$sf" \
      "$DBGEN_DIR/dbgen" -s "$sf" -T "$table"
  done
done
```

The codes select customer, orders, lineitem and nation respectively. Preserve
the standard `.tbl` format and filenames. SF1 and SF10 are generated separately.

## JOB 2013 IMDb snapshot

The CWI release describes the scope of use in its [snapshot notice](https://event.cwi.nl/da/job/readme.txt).
From `code/`, download and extract the five files needed by the mixed workload:

```sh
mkdir -p datasets/downloads datasets/imdb/csv
curl -fL --retry 3 https://event.cwi.nl/da/job/imdb.tgz \
  -o datasets/downloads/imdb.tgz
tar -xzf datasets/downloads/imdb.tgz -C datasets/imdb/csv \
  title.csv movie_companies.csv cast_info.csv kind_type.csv company_type.csv
```

Use the 2013 snapshot, retain its original CSV encoding and escaping, and keep
files readable by the operating-system account running PostgreSQL. The input
files and PostgreSQL working directories together require considerably more
space than the compressed downloads; allow at least 50 GB as a starting point.
Input presence alone does not establish byte identity with the original run.

The application workload uses generated synthetic tables. Its scale
configuration is included at `code/datasets/manifests/synthetic_saas_scales.yaml`.
