-- Marker row read by the benchmark driver to check which dataset is loaded.
-- scale is 'mixed' (SF1 + IMDb) or 'sf10'.  receipt is a fixed identifier of
-- the original input file set and is kept verbatim as data.
-- psql variables: scale, receipt.
CREATE SCHEMA native_af_bench;
CREATE TABLE native_af_bench.e3_input (scale text PRIMARY KEY, receipt text NOT NULL);
INSERT INTO native_af_bench.e3_input VALUES (:'scale', :'receipt');
