-- TPC-H subset used by the benchmark: customer, orders and lineitem, reduced
-- to the columns the queries and row policies use.  tenant_id is a synthetic
-- policy attribute derived from the customer key; region_id is the real
-- nation -> region mapping (shifted to start at 1).
--
-- Physical row order matters for the recorded plans, so this file must be
-- run exactly as written: one psql session, one statement per transaction
-- (psql autocommit), staging tables created in their own transaction before
-- they are loaded.  Row placement then follows PostgreSQL's ordinary heap
-- and free-space-map behaviour and is reproducible.
--
-- The .tbl files are pipe-delimited with a trailing '|'.  QUOTE is set to a
-- byte that never occurs in TPC-H text, which disables CSV quoting, and the
-- trailing delimiter loads into the extra _dummy column.
-- The data directory placeholder is filled in by the build script; in client
-- mode the COPY lines are run as psql \copy.

CREATE TABLE public.tpch_customer (
  c_custkey bigint PRIMARY KEY,
  c_mktsegment text NOT NULL,
  tenant_id bigint NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.tpch_orders (
  o_orderkey bigint PRIMARY KEY,
  o_custkey bigint NOT NULL,
  o_orderdate date NOT NULL,
  o_shippriority integer NOT NULL,
  tenant_id bigint NOT NULL
);
CREATE TABLE public.tpch_lineitem (
  l_orderkey bigint NOT NULL,
  l_extendedprice numeric(12,2) NOT NULL,
  l_discount numeric(5,4) NOT NULL,
  l_shipdate date NOT NULL
);
-- Staging tables keep every source column: their row width decides how COPY
-- places rows on pages, which in turn decides the final row order.
CREATE UNLOGGED TABLE public.stg_nation (
  n_nationkey int, n_name text, n_regionkey int, n_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_customer (
  c_custkey bigint, c_name text, c_address text, c_nationkey int, c_phone text,
  c_acctbal numeric, c_mktsegment text, c_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_orders (
  o_orderkey bigint, o_custkey bigint, o_orderstatus text, o_totalprice numeric,
  o_orderdate date, o_orderpriority text, o_clerk text, o_shippriority int,
  o_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_lineitem (
  l_orderkey bigint, l_partkey bigint, l_suppkey bigint, l_linenumber int,
  l_quantity numeric, l_extendedprice numeric, l_discount numeric, l_tax numeric,
  l_returnflag text, l_linestatus text, l_shipdate date, l_commitdate date,
  l_receiptdate date, l_shipinstruct text, l_shipmode text, l_comment text, _dummy text
);
COPY public.stg_nation FROM '@TPCH_DIR@/nation.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01');
COPY public.stg_customer FROM '@TPCH_DIR@/customer.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01');
COPY public.stg_orders FROM '@TPCH_DIR@/orders.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01');
COPY public.stg_lineitem FROM '@TPCH_DIR@/lineitem.tbl' WITH (FORMAT csv, DELIMITER '|', QUOTE E'\x01');
-- Rows are inserted in the staging tables' physical order.  The explicit
-- ORDER BY s.ctid states the order a hash join on the small dimension table
-- produces anyway; it keeps the result independent of planner settings.
INSERT INTO public.tpch_customer(c_custkey, c_mktsegment, tenant_id, region_id)
SELECT s.c_custkey, s.c_mktsegment, 1 + (s.c_custkey % 10), 1 + n.n_regionkey
FROM public.stg_customer s
JOIN public.stg_nation n ON n.n_nationkey = s.c_nationkey
ORDER BY s.ctid;
-- Single-table inserts read the staging table with one sequential scan
-- (synchronized scans are disabled by the build script), i.e. in ctid order.
INSERT INTO public.tpch_orders(o_orderkey, o_custkey, o_orderdate, o_shippriority, tenant_id)
SELECT o_orderkey, o_custkey, o_orderdate, o_shippriority, 1 + (o_custkey % 10)
FROM public.stg_orders;
INSERT INTO public.tpch_lineitem(l_orderkey, l_extendedprice, l_discount, l_shipdate)
SELECT l_orderkey, l_extendedprice, l_discount, l_shipdate
FROM public.stg_lineitem;
DROP TABLE public.stg_lineitem;
DROP TABLE public.stg_orders;
DROP TABLE public.stg_customer;
DROP TABLE public.stg_nation;
CREATE INDEX tpch_customer_tenant_idx ON public.tpch_customer(tenant_id, c_custkey);
CREATE INDEX tpch_orders_cust_date_idx ON public.tpch_orders(o_custkey, o_orderdate);
CREATE INDEX tpch_lineitem_order_ship_idx ON public.tpch_lineitem(l_orderkey, l_shipdate);
ANALYZE public.tpch_customer;
ANALYZE public.tpch_orders;
ANALYZE public.tpch_lineitem;
