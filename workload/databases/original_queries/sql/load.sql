-- Load the "original queries" benchmark database: full TPC-H SF1 (8 tables) and the
-- full IMDb schema used by the Join Order Benchmark (21 tables), plus tenant columns,
-- the ACL/group tables used by the row-level-security policies, secondary indexes,
-- the ordinary (non-superuser) reader role and its grants.
--
-- Run with psql as the bootstrap superuser "postgres", connected to the freshly created
-- target database, with two psql variables:
--   tpch_dir  directory holding the eight dbgen SF1 files (nation.tbl ... lineitem.tbl)
--   imdb_dir  directory holding the 21 IMDb CSV files (unpacked imdb.tgz)
-- build.sh does this for you.  Every statement runs in its own transaction (autocommit),
-- in exactly the order used for the reference database; do not reorder statements.
--
-- Physical row order: COPY appends rows in file order and every INSERT ... SELECT
-- appends rows in the order its plan produces them.  The lineitem INSERT joins the staged
-- lineitem rows with orders; with the settings below the planner picks a multi-batch hash
-- join, so lineitem is stored batch by batch rather than in lineitem.tbl order.  The
-- planner/executor settings are therefore pinned here to the values the reference
-- database was loaded with.  Autovacuum must be off on the server during the load
-- (build.sh checks this), otherwise background ANALYZE can change that plan.

\set ON_ERROR_STOP on
SET client_encoding = 'UTF8';
SET statement_timeout = 0;
SET search_path = public;
SET maintenance_work_mem = '256MB';
SET work_mem = '16MB';
SET hash_mem_multiplier = 2.0;
SET effective_cache_size = '8GB';
SET seq_page_cost = 1.0;
SET random_page_cost = 4.0;
SET cpu_tuple_cost = 0.01;
SET cpu_index_tuple_cost = 0.005;
SET cpu_operator_cost = 0.0025;
SET jit = off;
SET max_parallel_workers_per_gather = 0;
SET max_parallel_maintenance_workers = 0;
SET enable_seqscan = on;
SET enable_indexscan = on;
SET enable_indexonlyscan = on;
SET enable_bitmapscan = on;
SET enable_tidscan = on;
SET enable_sort = on;
SET enable_incremental_sort = on;
SET enable_hashagg = on;
SET enable_material = on;
SET enable_memoize = on;
SET enable_nestloop = on;
SET enable_mergejoin = on;
SET enable_hashjoin = on;
SET enable_presorted_aggregate = on;
SET synchronize_seqscans = off;
SET default_toast_compression = 'pglz';
SET default_table_access_method = 'heap';
SET default_tablespace = '';
SET default_statistics_target = 100;

-- Ordinary reader role used for every measured query (no superuser, no BYPASSRLS,
-- NOINHERIT, no memberships).  It is cluster-wide; reuse it if it already exists.
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='caprls_e3_rls_user') THEN CREATE ROLE caprls_e3_rls_user LOGIN NOINHERIT NOBYPASSRLS; END IF; END $$;

-- Schema holding trusted reference views; their definitions are installed by finalize.sql.
CREATE SCHEMA a031_expected;

-- ---------------------------------------------------------------------------
-- TPC-H SF1.  Each .tbl file is staged into an unlogged table (the trailing '|' of the
-- dbgen format becomes the unused _dummy column) and copied into the final table.
-- customer and orders get tenant_id = 1 + (custkey % 10); lineitem inherits the tenant
-- of its order through a join with orders, whose primary key already exists then.
-- ---------------------------------------------------------------------------
\cd :tpch_dir
CREATE TABLE public.nation (n_nationkey BIGINT NOT NULL, n_name CHAR(25) NOT NULL, n_regionkey BIGINT NOT NULL, n_comment VARCHAR(152));
CREATE UNLOGGED TABLE public.load_stage_nation (n_nationkey BIGINT, n_name CHAR(25), n_regionkey BIGINT, n_comment VARCHAR(152), _dummy text);
\copy public.load_stage_nation FROM 'nation.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.nation (n_nationkey, n_name, n_regionkey, n_comment) SELECT n_nationkey, n_name, n_regionkey, n_comment FROM public.load_stage_nation;
DROP TABLE public.load_stage_nation;
CREATE TABLE public.region (r_regionkey BIGINT NOT NULL, r_name CHAR(25) NOT NULL, r_comment VARCHAR(152));
CREATE UNLOGGED TABLE public.load_stage_region (r_regionkey BIGINT, r_name CHAR(25), r_comment VARCHAR(152), _dummy text);
\copy public.load_stage_region FROM 'region.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.region (r_regionkey, r_name, r_comment) SELECT r_regionkey, r_name, r_comment FROM public.load_stage_region;
DROP TABLE public.load_stage_region;
CREATE TABLE public.part (p_partkey BIGINT NOT NULL, p_name VARCHAR(55) NOT NULL, p_mfgr CHAR(25) NOT NULL, p_brand CHAR(10) NOT NULL, p_type VARCHAR(25) NOT NULL, p_size INTEGER NOT NULL, p_container CHAR(10) NOT NULL, p_retailprice DECIMAL(15,2) NOT NULL, p_comment VARCHAR(23) NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_part (p_partkey BIGINT, p_name VARCHAR(55), p_mfgr CHAR(25), p_brand CHAR(10), p_type VARCHAR(25), p_size INTEGER, p_container CHAR(10), p_retailprice DECIMAL(15,2), p_comment VARCHAR(23), _dummy text);
\copy public.load_stage_part FROM 'part.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.part (p_partkey, p_name, p_mfgr, p_brand, p_type, p_size, p_container, p_retailprice, p_comment) SELECT p_partkey, p_name, p_mfgr, p_brand, p_type, p_size, p_container, p_retailprice, p_comment FROM public.load_stage_part;
DROP TABLE public.load_stage_part;
CREATE TABLE public.supplier (s_suppkey BIGINT NOT NULL, s_name CHAR(25) NOT NULL, s_address VARCHAR(40) NOT NULL, s_nationkey BIGINT NOT NULL, s_phone CHAR(15) NOT NULL, s_acctbal DECIMAL(15,2) NOT NULL, s_comment VARCHAR(101) NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_supplier (s_suppkey BIGINT, s_name CHAR(25), s_address VARCHAR(40), s_nationkey BIGINT, s_phone CHAR(15), s_acctbal DECIMAL(15,2), s_comment VARCHAR(101), _dummy text);
\copy public.load_stage_supplier FROM 'supplier.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.supplier (s_suppkey, s_name, s_address, s_nationkey, s_phone, s_acctbal, s_comment) SELECT s_suppkey, s_name, s_address, s_nationkey, s_phone, s_acctbal, s_comment FROM public.load_stage_supplier;
DROP TABLE public.load_stage_supplier;
CREATE TABLE public.partsupp (ps_partkey BIGINT NOT NULL, ps_suppkey BIGINT NOT NULL, ps_availqty INTEGER NOT NULL, ps_supplycost DECIMAL(15,2)  NOT NULL, ps_comment VARCHAR(199) NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_partsupp (ps_partkey BIGINT, ps_suppkey BIGINT, ps_availqty INTEGER, ps_supplycost DECIMAL(15,2), ps_comment VARCHAR(199), _dummy text);
\copy public.load_stage_partsupp FROM 'partsupp.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.partsupp (ps_partkey, ps_suppkey, ps_availqty, ps_supplycost, ps_comment) SELECT ps_partkey, ps_suppkey, ps_availqty, ps_supplycost, ps_comment FROM public.load_stage_partsupp;
DROP TABLE public.load_stage_partsupp;
CREATE TABLE public.customer (c_custkey BIGINT NOT NULL, c_name VARCHAR(25) NOT NULL, c_address VARCHAR(40) NOT NULL, c_nationkey BIGINT NOT NULL, c_phone CHAR(15) NOT NULL, c_acctbal DECIMAL(15,2)   NOT NULL, c_mktsegment CHAR(10) NOT NULL, c_comment VARCHAR(117) NOT NULL, tenant_id bigint NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_customer (c_custkey BIGINT, c_name VARCHAR(25), c_address VARCHAR(40), c_nationkey BIGINT, c_phone CHAR(15), c_acctbal DECIMAL(15,2), c_mktsegment CHAR(10), c_comment VARCHAR(117), _dummy text);
\copy public.load_stage_customer FROM 'customer.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.customer (c_custkey, c_name, c_address, c_nationkey, c_phone, c_acctbal, c_mktsegment, c_comment,tenant_id) SELECT c_custkey, c_name, c_address, c_nationkey, c_phone, c_acctbal, c_mktsegment, c_comment,1+(c_custkey%10) FROM public.load_stage_customer;
DROP TABLE public.load_stage_customer;
CREATE TABLE public.orders (o_orderkey BIGINT NOT NULL, o_custkey BIGINT NOT NULL, o_orderstatus CHAR(1) NOT NULL, o_totalprice DECIMAL(15,2) NOT NULL, o_orderdate DATE NOT NULL, o_orderpriority CHAR(15) NOT NULL, o_clerk CHAR(15) NOT NULL, o_shippriority INTEGER NOT NULL, o_comment VARCHAR(79) NOT NULL, tenant_id bigint NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_orders (o_orderkey BIGINT, o_custkey BIGINT, o_orderstatus CHAR(1), o_totalprice DECIMAL(15,2), o_orderdate DATE, o_orderpriority CHAR(15), o_clerk CHAR(15), o_shippriority INTEGER, o_comment VARCHAR(79), _dummy text);
\copy public.load_stage_orders FROM 'orders.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.orders (o_orderkey, o_custkey, o_orderstatus, o_totalprice, o_orderdate, o_orderpriority, o_clerk, o_shippriority, o_comment,tenant_id) SELECT o_orderkey, o_custkey, o_orderstatus, o_totalprice, o_orderdate, o_orderpriority, o_clerk, o_shippriority, o_comment,1+(o_custkey%10) FROM public.load_stage_orders;
DROP TABLE public.load_stage_orders;
ALTER TABLE public.orders ADD PRIMARY KEY (o_orderkey);
CREATE TABLE public.lineitem (l_orderkey BIGINT NOT NULL, l_partkey BIGINT NOT NULL, l_suppkey BIGINT NOT NULL, l_linenumber INTEGER NOT NULL, l_quantity DECIMAL(15,2) NOT NULL, l_extendedprice DECIMAL(15,2) NOT NULL, l_discount DECIMAL(15,2) NOT NULL, l_tax DECIMAL(15,2) NOT NULL, l_returnflag CHAR(1) NOT NULL, l_linestatus CHAR(1) NOT NULL, l_shipdate DATE NOT NULL, l_commitdate DATE NOT NULL, l_receiptdate DATE NOT NULL, l_shipinstruct CHAR(25) NOT NULL, l_shipmode CHAR(10) NOT NULL, l_comment VARCHAR(44) NOT NULL, tenant_id bigint NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_lineitem (l_orderkey BIGINT, l_partkey BIGINT, l_suppkey BIGINT, l_linenumber INTEGER, l_quantity DECIMAL(15,2), l_extendedprice DECIMAL(15,2), l_discount DECIMAL(15,2), l_tax DECIMAL(15,2), l_returnflag CHAR(1), l_linestatus CHAR(1), l_shipdate DATE, l_commitdate DATE, l_receiptdate DATE, l_shipinstruct CHAR(25), l_shipmode CHAR(10), l_comment VARCHAR(44), _dummy text);
\copy public.load_stage_lineitem FROM 'lineitem.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01')
INSERT INTO public.lineitem (l_orderkey, l_partkey, l_suppkey, l_linenumber, l_quantity, l_extendedprice, l_discount, l_tax, l_returnflag, l_linestatus, l_shipdate, l_commitdate, l_receiptdate, l_shipinstruct, l_shipmode, l_comment,tenant_id) SELECT s.l_orderkey, s.l_partkey, s.l_suppkey, s.l_linenumber, s.l_quantity, s.l_extendedprice, s.l_discount, s.l_tax, s.l_returnflag, s.l_linestatus, s.l_shipdate, s.l_commitdate, s.l_receiptdate, s.l_shipinstruct, s.l_shipmode, s.l_comment,o.tenant_id FROM public.load_stage_lineitem s JOIN public.orders o ON o.o_orderkey=s.l_orderkey;
DROP TABLE public.load_stage_lineitem;
ALTER TABLE public.nation ADD PRIMARY KEY (n_nationkey);
ALTER TABLE public.region ADD PRIMARY KEY (r_regionkey);
ALTER TABLE public.part ADD PRIMARY KEY (p_partkey);
ALTER TABLE public.supplier ADD PRIMARY KEY (s_suppkey);
ALTER TABLE public.partsupp ADD PRIMARY KEY (ps_partkey,ps_suppkey);
ALTER TABLE public.customer ADD PRIMARY KEY (c_custkey);
ALTER TABLE public.lineitem ADD PRIMARY KEY (l_orderkey,l_linenumber);

-- ---------------------------------------------------------------------------
-- IMDb (Join Order Benchmark), all keys BIGINT.  Tables are loaded directly with COPY,
-- except title, which is staged so that tenant_id = 1 + (id % 5) can be added.
-- ---------------------------------------------------------------------------
\cd :imdb_dir
CREATE TABLE public.aka_name (id bigint NOT NULL, person_id bigint NOT NULL, name text NOT NULL, imdb_index character varying(12), name_pcode_cf character varying(5), name_pcode_nf character varying(5), surname_pcode character varying(5), md5sum character varying(32));
\copy public.aka_name (id,person_id,name,imdb_index,name_pcode_cf,name_pcode_nf,surname_pcode,md5sum) FROM 'aka_name.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.aka_name ADD PRIMARY KEY (id);
CREATE TABLE public.aka_title (id bigint NOT NULL, movie_id bigint NOT NULL, title text NOT NULL, imdb_index character varying(12), kind_id bigint NOT NULL, production_year integer, phonetic_code character varying(5), episode_of_id bigint, season_nr integer, episode_nr integer, note text, md5sum character varying(32));
\copy public.aka_title (id,movie_id,title,imdb_index,kind_id,production_year,phonetic_code,episode_of_id,season_nr,episode_nr,note,md5sum) FROM 'aka_title.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.aka_title ADD PRIMARY KEY (id);
CREATE TABLE public.cast_info (id bigint NOT NULL, person_id bigint NOT NULL, movie_id bigint NOT NULL, person_role_id bigint, note text, nr_order integer, role_id bigint NOT NULL);
\copy public.cast_info (id,person_id,movie_id,person_role_id,note,nr_order,role_id) FROM 'cast_info.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.cast_info ADD PRIMARY KEY (id);
CREATE TABLE public.char_name (id bigint NOT NULL, name text NOT NULL, imdb_index character varying(12), imdb_id bigint, name_pcode_nf character varying(5), surname_pcode character varying(5), md5sum character varying(32));
\copy public.char_name (id,name,imdb_index,imdb_id,name_pcode_nf,surname_pcode,md5sum) FROM 'char_name.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.char_name ADD PRIMARY KEY (id);
CREATE TABLE public.comp_cast_type (id bigint NOT NULL, kind character varying(32) NOT NULL);
\copy public.comp_cast_type (id,kind) FROM 'comp_cast_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.comp_cast_type ADD PRIMARY KEY (id);
CREATE TABLE public.company_name (id bigint NOT NULL, name text NOT NULL, country_code character varying(255), imdb_id bigint, name_pcode_nf character varying(5), name_pcode_sf character varying(5), md5sum character varying(32));
\copy public.company_name (id,name,country_code,imdb_id,name_pcode_nf,name_pcode_sf,md5sum) FROM 'company_name.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.company_name ADD PRIMARY KEY (id);
CREATE TABLE public.company_type (id bigint NOT NULL, kind character varying(32) NOT NULL);
\copy public.company_type (id,kind) FROM 'company_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.company_type ADD PRIMARY KEY (id);
CREATE TABLE public.complete_cast (id bigint NOT NULL, movie_id bigint, subject_id bigint NOT NULL, status_id bigint NOT NULL);
\copy public.complete_cast (id,movie_id,subject_id,status_id) FROM 'complete_cast.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.complete_cast ADD PRIMARY KEY (id);
CREATE TABLE public.info_type (id bigint NOT NULL, info character varying(32) NOT NULL);
\copy public.info_type (id,info) FROM 'info_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.info_type ADD PRIMARY KEY (id);
CREATE TABLE public.keyword (id bigint NOT NULL, keyword text NOT NULL, phonetic_code character varying(5));
\copy public.keyword (id,keyword,phonetic_code) FROM 'keyword.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.keyword ADD PRIMARY KEY (id);
CREATE TABLE public.kind_type (id bigint NOT NULL, kind character varying(15) NOT NULL);
\copy public.kind_type (id,kind) FROM 'kind_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.kind_type ADD PRIMARY KEY (id);
CREATE TABLE public.link_type (id bigint NOT NULL, link character varying(32) NOT NULL);
\copy public.link_type (id,link) FROM 'link_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.link_type ADD PRIMARY KEY (id);
CREATE TABLE public.movie_companies (id bigint NOT NULL, movie_id bigint NOT NULL, company_id bigint NOT NULL, company_type_id bigint NOT NULL, note text);
\copy public.movie_companies (id,movie_id,company_id,company_type_id,note) FROM 'movie_companies.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.movie_companies ADD PRIMARY KEY (id);
CREATE TABLE public.movie_info (id bigint NOT NULL, movie_id bigint NOT NULL, info_type_id bigint NOT NULL, info text NOT NULL, note text);
\copy public.movie_info (id,movie_id,info_type_id,info,note) FROM 'movie_info.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.movie_info ADD PRIMARY KEY (id);
CREATE TABLE public.movie_info_idx (id bigint NOT NULL, movie_id bigint NOT NULL, info_type_id bigint NOT NULL, info text NOT NULL, note text);
\copy public.movie_info_idx (id,movie_id,info_type_id,info,note) FROM 'movie_info_idx.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.movie_info_idx ADD PRIMARY KEY (id);
CREATE TABLE public.movie_keyword (id bigint NOT NULL, movie_id bigint NOT NULL, keyword_id bigint NOT NULL);
\copy public.movie_keyword (id,movie_id,keyword_id) FROM 'movie_keyword.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.movie_keyword ADD PRIMARY KEY (id);
CREATE TABLE public.movie_link (id bigint NOT NULL, movie_id bigint NOT NULL, linked_movie_id bigint NOT NULL, link_type_id bigint NOT NULL);
\copy public.movie_link (id,movie_id,linked_movie_id,link_type_id) FROM 'movie_link.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.movie_link ADD PRIMARY KEY (id);
CREATE TABLE public.name (id bigint NOT NULL, name text NOT NULL, imdb_index character varying(12), imdb_id bigint, gender character varying(1), name_pcode_cf character varying(5), name_pcode_nf character varying(5), surname_pcode character varying(5), md5sum character varying(32));
\copy public.name (id,name,imdb_index,imdb_id,gender,name_pcode_cf,name_pcode_nf,surname_pcode,md5sum) FROM 'name.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.name ADD PRIMARY KEY (id);
CREATE TABLE public.person_info (id bigint NOT NULL, person_id bigint NOT NULL, info_type_id bigint NOT NULL, info text NOT NULL, note text);
\copy public.person_info (id,person_id,info_type_id,info,note) FROM 'person_info.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.person_info ADD PRIMARY KEY (id);
CREATE TABLE public.role_type (id bigint NOT NULL, role character varying(32) NOT NULL);
\copy public.role_type (id,role) FROM 'role_type.csv' WITH (FORMAT csv, ESCAPE '\')
ALTER TABLE public.role_type ADD PRIMARY KEY (id);
CREATE TABLE public.title (id bigint NOT NULL, title text NOT NULL, imdb_index character varying(12), kind_id bigint NOT NULL, production_year integer, imdb_id bigint, phonetic_code character varying(5), episode_of_id bigint, season_nr integer, episode_nr integer, series_years character varying(49), md5sum character varying(32), tenant_id bigint NOT NULL);
CREATE UNLOGGED TABLE public.load_stage_title (id bigint NOT NULL,title text NOT NULL,imdb_index character varying(12),kind_id bigint NOT NULL,production_year integer,imdb_id bigint,phonetic_code character varying(5),episode_of_id bigint,season_nr integer,episode_nr integer,series_years character varying(49),md5sum character varying(32));
\copy public.load_stage_title (id,title,imdb_index,kind_id,production_year,imdb_id,phonetic_code,episode_of_id,season_nr,episode_nr,series_years,md5sum) FROM 'title.csv' WITH (FORMAT csv, ESCAPE '\')
INSERT INTO public.title (id,title,imdb_index,kind_id,production_year,imdb_id,phonetic_code,episode_of_id,season_nr,episode_nr,series_years,md5sum,tenant_id) SELECT id,title,imdb_index,kind_id,production_year,imdb_id,phonetic_code,episode_of_id,season_nr,episode_nr,series_years,md5sum,1+(id%5) FROM public.load_stage_title;
DROP TABLE public.load_stage_title;
ALTER TABLE public.title ADD PRIMARY KEY (id);

-- Standard Join Order Benchmark foreign-key indexes.
create index company_id_movie_companies on movie_companies(company_id);
create index company_type_id_movie_companies on movie_companies(company_type_id);
create index info_type_id_movie_info_idx on movie_info_idx(info_type_id);
create index info_type_id_movie_info on movie_info(info_type_id);
create index info_type_id_person_info on person_info(info_type_id);
create index keyword_id_movie_keyword on movie_keyword(keyword_id);
create index kind_id_aka_title on aka_title(kind_id);
create index kind_id_title on title(kind_id);
create index linked_movie_id_movie_link on movie_link(linked_movie_id);
create index link_type_id_movie_link on movie_link(link_type_id);
create index movie_id_aka_title on aka_title(movie_id);
create index movie_id_cast_info on cast_info(movie_id);
create index movie_id_complete_cast on complete_cast(movie_id);
create index movie_id_movie_companies on movie_companies(movie_id);
create index movie_id_movie_info_idx on movie_info_idx(movie_id);
create index movie_id_movie_keyword on movie_keyword(movie_id);
create index movie_id_movie_link on movie_link(movie_id);
create index movie_id_movie_info on movie_info(movie_id);
create index person_id_aka_name on aka_name(person_id);
create index person_id_cast_info on cast_info(person_id);
create index person_id_person_info on person_info(person_id);
create index person_role_id_cast_info on cast_info(person_role_id);
create index role_id_cast_info on cast_info(role_id);

-- TPC-H secondary indexes.
CREATE INDEX customer_nation_idx ON customer(c_nationkey);
CREATE INDEX orders_customer_date_idx ON orders(o_custkey,o_orderdate);
CREATE INDEX orders_date_idx ON orders(o_orderdate);
CREATE INDEX lineitem_supplier_idx ON lineitem(l_suppkey);
CREATE INDEX lineitem_part_supplier_idx ON lineitem(l_partkey,l_suppkey);
CREATE INDEX partsupp_supplier_idx ON partsupp(ps_suppkey);
CREATE INDEX supplier_nation_idx ON supplier(s_nationkey);
CREATE INDEX nation_region_idx ON nation(n_regionkey);
CREATE INDEX customer_segment_idx ON customer(c_mktsegment);

-- ---------------------------------------------------------------------------
-- ACL tables for the membership policies.  Principal 'e3_user' is in group 1, and group 1
-- may read every customer with c_custkey % 10 = 0 and every title with id % 10 = 0.
-- The rows are derived deterministically from the loaded data (no randomness).
-- ---------------------------------------------------------------------------
CREATE TABLE public.group_membership (user_id text NOT NULL, group_id bigint NOT NULL,
            membership_version bigint NOT NULL DEFAULT 0, PRIMARY KEY(user_id,group_id));
CREATE TABLE public.share_acl (relname text NOT NULL,rid bigint NOT NULL,group_id bigint NOT NULL,
            permission text NOT NULL,acl_version bigint NOT NULL DEFAULT 0,
            PRIMARY KEY(relname,rid,group_id,permission));
INSERT INTO group_membership(user_id,group_id) VALUES ('e3_user',1);
INSERT INTO share_acl(relname,rid,group_id,permission) SELECT 'public.customer',c_custkey,1,'read' FROM customer WHERE c_custkey%10=0;
INSERT INTO share_acl(relname,rid,group_id,permission) SELECT 'public.title',id,1,'read' FROM title WHERE id%10=0;
CREATE INDEX share_acl_lookup_idx ON share_acl(relname,rid,permission,group_id);
CREATE INDEX share_acl_group_idx ON share_acl(group_id,relname,permission);

-- Partial indexes over the key-subset ("key" policy) predicates.
CREATE INDEX native_af_auth_customer_segment_key ON customer(c_mktsegment,c_custkey) WHERE tenant_id=1 AND (c_custkey%50::bigint)=0;
CREATE INDEX native_af_auth_title_kind_key ON title(kind_id,id) WHERE tenant_id=1 AND (id%50::bigint)=0;

-- Read access for the reader role (the marker table below is created afterwards and is
-- intentionally not granted).
GRANT USAGE ON SCHEMA public TO caprls_e3_rls_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO caprls_e3_rls_user;

-- Identity marker checked by the benchmark driver before it runs any condition.
CREATE TABLE public.a031_b_marker(identity text PRIMARY KEY);
INSERT INTO public.a031_b_marker VALUES ('a031-full-schema-b-r01');

-- Final maintenance exactly as for the reference database: one database-wide
-- VACUUM (FREEZE, ANALYZE).  No later VACUUM or ANALYZE was ever run on it.
VACUUM (FREEZE, ANALYZE);
