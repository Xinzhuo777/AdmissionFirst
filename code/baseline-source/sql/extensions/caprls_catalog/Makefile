EXTENSION = caprls_catalog
MODULE_big = caprls_catalog
OBJS = caprls_catalog.o
DATA = caprls_catalog--1.0.sql
PGFILEDESC = "caprls_catalog - CAPRLS path-integration witness"

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
