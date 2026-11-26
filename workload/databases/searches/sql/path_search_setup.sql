-- Document-path-search fixture: one million documents in 16 tenants with
-- hierarchical paths, two ACL rows per document (two independent group
-- domains), and group memberships for three principals.
--
-- Run this file once, as the bootstrap superuser "postgres", in a freshly
-- created, empty database (see build_path_search.sh), then run
-- path_search_post_load.sql in a separate session.  Every statement must
-- stay exactly as written and in this order: the row values, the physical
-- placement of every row (ctid) and the index shapes all follow from it.
-- The whole load is one transaction.
BEGIN;
SET LOCAL default_statistics_target = 1000;
SET LOCAL standard_conforming_strings = on;
-- Refuse to run twice: the load must start from new, empty tables.
DO $fresh$
BEGIN
    IF to_regclass('public.a027_document') IS NOT NULL OR
       to_regclass('public.a027_share_acl') IS NOT NULL OR
       to_regclass('public.a027_group_membership') IS NOT NULL THEN
        RAISE EXCEPTION 'path-search fixture tables already exist; load into a new empty database';
    END IF;
END
$fresh$;
-- The three reader principals (created once per cluster, then reused).
DO $roles$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['a027_ind_sparse','a027_ind_dense','a027_corr_sparse'] LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=role_name) THEN
            EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', role_name);
        END IF;
        IF EXISTS (SELECT FROM pg_roles WHERE rolname=role_name AND
                   (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR
                    rolreplication OR rolinherit OR NOT rolcanlogin)) THEN
            RAISE EXCEPTION 'fixture role % has incompatible attributes', role_name;
        END IF;
    END LOOP;
END
$roles$;

CREATE TABLE public.a027_document (
    id bigint PRIMARY KEY,
    tenant_id bigint NOT NULL,
    path text COLLATE "C",
    title text COLLATE "C"
);
CREATE TABLE public.a027_share_acl (
    relname text NOT NULL,
    rid bigint NOT NULL,
    group_id bigint NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (relname,rid,group_id,permission)
);
CREATE TABLE public.a027_group_membership (
    user_id text NOT NULL,
    group_id bigint NOT NULL,
    PRIMARY KEY (user_id,group_id)
);

-- Documents.  Tenant, path prefix, kind and topic come from independent md5
-- hashes of the id (the hash salts are data and must not change).
WITH buckets AS (
    SELECT id,
           1+(('x'||substr(md5('a027-tenant:'||id),1,8))::bit(32)::bigint % 16) AS tenant_id,
           (('x'||substr(md5('a027-path:'||id),1,8))::bit(32)::bigint % 1000) AS path_bucket,
           (('x'||substr(md5('a027-kind:'||id),1,8))::bit(32)::bigint % 2) AS kind,
           (('x'||substr(md5('a027-display:'||id),1,8))::bit(32)::bigint % 64) AS topic
    FROM generate_series(1,1000000) AS ids(id)
)
INSERT INTO public.a027_document
SELECT id, tenant_id,
       CASE WHEN id % 173=0 THEN NULL ELSE
           CASE WHEN path_bucket=0 THEN 'docs/security/auth/'
                WHEN path_bucket<10 THEN 'docs/security/guide/'
                WHEN path_bucket<200 THEN 'docs/product/'
                ELSE 'notes/' END ||
           CASE WHEN kind=0 THEN 'rotation-' ELSE 'setup-' END ||
           topic::text || '-' || lpad(id::text,10,'0') END,
       CASE WHEN id % 257=0 THEN NULL ELSE
           'Workspace '||tenant_id::text||' topic '||topic::text||' document '||id::text END
FROM buckets;

-- Fixed anchor rows overwrite ids 1..8 (they do not add rows).  These
-- UPDATEs move the eight rows to the end of the heap; that placement is
-- part of the fixture.
UPDATE public.a027_document SET tenant_id=1,path='docs/security/auth/rotation-shared',title='Access key rotation' WHERE id IN (1,2,3);
UPDATE public.a027_document SET tenant_id=2,path='docs/security/auth/rotation-empty-title',title=NULL WHERE id IN (4,5);
UPDATE public.a027_document SET tenant_id=1,path=NULL,title='Null path control' WHERE id=6;
UPDATE public.a027_document SET tenant_id=1,path='docs/security/auth/setup-guide',title='Exact LIKE recheck control' WHERE id=7;
UPDATE public.a027_document SET tenant_id=16,path='docs/security/auth/rotation-%literal',title='Literal percent in stored path' WHERE id=8;

-- First ACL domain (groups 0..15999), one row per document in heap order.
INSERT INTO public.a027_share_acl
SELECT 'public.a027_document', id, (tenant_id-1)*1000 +
       CASE WHEN id=2 THEN 1 WHEN id IN (3,5) THEN 999
            WHEN id IN (1,4,6,7,8) THEN 0
            ELSE (('x'||substr(md5('a027-acl:'||id),1,8))::bit(32)::bigint % 1000) END,
       'read'
FROM public.a027_document;
-- Second ACL domain (groups 1000000..1015999), correlated with the path.
INSERT INTO public.a027_share_acl
SELECT 'public.a027_document', id, 1000000+(tenant_id-1)*1000 +
       CASE WHEN id=2 THEN 1 WHEN id IN (3,5) THEN 999
            WHEN id IN (1,4,6,7,8) THEN 0
            ELSE (('x'||substr(md5('a027-path:'||id),1,8))::bit(32)::bigint % 1000) END,
       'read'
FROM public.a027_document;
-- Extra ACL rows: second authorizing groups for documents 1 and 2.
INSERT INTO public.a027_share_acl VALUES
 ('public.a027_document',1,2,'read'),
 ('public.a027_document',1,1000002,'read'),
 ('public.a027_document',2,2,'read'),
 ('public.a027_document',2,1000002,'read');

-- Memberships: per tenant, sparse = 10 groups, dense = 800 groups (first
-- domain); the correlated principal has 10 groups per tenant in the second
-- domain.
INSERT INTO public.a027_group_membership
SELECT principal, domain_offset+tenant*1000+local_group
FROM (VALUES ('a027_ind_sparse',0::bigint,10),
             ('a027_ind_dense',0::bigint,800),
             ('a027_corr_sparse',1000000::bigint,10))
     AS users(principal,domain_offset,memberships)
CROSS JOIN generate_series(0,15) AS tenants(tenant)
CROSS JOIN LATERAL generate_series(0,memberships-1) AS groups(local_group);

CREATE INDEX a027_document_path_pattern ON public.a027_document (path COLLATE "C" text_pattern_ops);
CREATE INDEX a027_acl_group ON public.a027_share_acl (group_id,relname,permission,rid);
ALTER TABLE public.a027_document ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.a027_document FORCE ROW LEVEL SECURITY;
CREATE POLICY a027_sparse ON public.a027_document FOR SELECT TO a027_ind_sparse USING (
    EXISTS (SELECT 1 FROM public.a027_share_acl s
            JOIN public.a027_group_membership m ON m.group_id=s.group_id
            WHERE m.user_id='a027_ind_sparse' AND s.relname='public.a027_document'
              AND s.rid=a027_document.id AND s.permission='read')
);
CREATE POLICY a027_dense ON public.a027_document FOR SELECT TO a027_ind_dense USING (
    EXISTS (SELECT 1 FROM public.a027_share_acl s
            JOIN public.a027_group_membership m ON m.group_id=s.group_id
            WHERE m.user_id='a027_ind_dense' AND s.relname='public.a027_document'
              AND s.rid=a027_document.id AND s.permission='read')
);
CREATE POLICY a027_correlated ON public.a027_document FOR SELECT TO a027_corr_sparse USING (
    EXISTS (SELECT 1 FROM public.a027_share_acl s
            JOIN public.a027_group_membership m ON m.group_id=s.group_id
            WHERE m.user_id='a027_corr_sparse' AND s.relname='public.a027_document'
              AND s.rid=a027_document.id AND s.permission='read')
);
GRANT USAGE ON SCHEMA public TO a027_ind_sparse,a027_ind_dense,a027_corr_sparse;
GRANT SELECT ON public.a027_document,public.a027_share_acl,public.a027_group_membership
    TO a027_ind_sparse,a027_ind_dense,a027_corr_sparse;

-- Persistent per-column statistics targets (also used by the post-load
-- ANALYZE).
ALTER TABLE public.a027_document ALTER COLUMN id SET STATISTICS 1000;
ALTER TABLE public.a027_document ALTER COLUMN tenant_id SET STATISTICS 1000;
ALTER TABLE public.a027_document ALTER COLUMN path SET STATISTICS 1000;
ALTER TABLE public.a027_document ALTER COLUMN title SET STATISTICS 1000;
ALTER TABLE public.a027_share_acl ALTER COLUMN relname SET STATISTICS 1000;
ALTER TABLE public.a027_share_acl ALTER COLUMN rid SET STATISTICS 1000;
ALTER TABLE public.a027_share_acl ALTER COLUMN group_id SET STATISTICS 1000;
ALTER TABLE public.a027_share_acl ALTER COLUMN permission SET STATISTICS 1000;
ALTER TABLE public.a027_group_membership ALTER COLUMN user_id SET STATISTICS 1000;
ALTER TABLE public.a027_group_membership ALTER COLUMN group_id SET STATISTICS 1000;
COMMIT;
