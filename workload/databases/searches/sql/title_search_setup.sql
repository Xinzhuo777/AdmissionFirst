-- Title-search fixture: 524,288 documents with prefix-structured titles, a
-- share ACL, group memberships for three principals, an audit table and an
-- audit logging function.
--
-- Run this file once, as the bootstrap superuser "postgres", in a freshly
-- created, empty database (see build_title_search.sh).  Every statement must
-- stay exactly as written and in this order: the row values, the physical
-- placement of every row (ctid) and the index shapes all follow from it.
-- The whole load is one transaction.
BEGIN;
-- Statistics target used by the ANALYZE commands at the end of this file
-- (session-local; not stored as a per-column setting).
SET LOCAL default_statistics_target = 1000;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_sparse') THEN CREATE ROLE af_prefix_sparse LOGIN NOSUPERUSER NOBYPASSRLS; END IF; IF EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_sparse' AND (rolsuper OR rolbypassrls OR NOT rolcanlogin)) THEN RAISE EXCEPTION 'fixture role has incompatible attributes'; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_medium') THEN CREATE ROLE af_prefix_medium LOGIN NOSUPERUSER NOBYPASSRLS; END IF; IF EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_medium' AND (rolsuper OR rolbypassrls OR NOT rolcanlogin)) THEN RAISE EXCEPTION 'fixture role has incompatible attributes'; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_dense') THEN CREATE ROLE af_prefix_dense LOGIN NOSUPERUSER NOBYPASSRLS; END IF; IF EXISTS (SELECT FROM pg_roles WHERE rolname='af_prefix_dense' AND (rolsuper OR rolbypassrls OR NOT rolcanlogin)) THEN RAISE EXCEPTION 'fixture role has incompatible attributes'; END IF; END $$;
CREATE TABLE public.prefix_doc (
    id bigint PRIMARY KEY,
    title text COLLATE "C",
    secret text
);
CREATE TABLE public.group_membership (
    user_id text NOT NULL,
    group_id bigint NOT NULL,
    PRIMARY KEY (user_id, group_id)
);
CREATE TABLE public.share_acl (
    relname text NOT NULL,
    rid bigint NOT NULL,
    group_id bigint NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (relname, rid, group_id, permission)
);
CREATE INDEX prefix_acl_group ON public.share_acl (group_id, relname, permission, rid);
-- Memberships: the sparse, medium and dense principals belong to groups
-- 0..0, 0..49 and 0..799 of 1,000 groups.
INSERT INTO public.group_membership
SELECT principal, group_id
FROM (VALUES ('af_prefix_sparse', 1), ('af_prefix_medium', 50),
             ('af_prefix_dense', 800)) AS users(principal, memberships)
CROSS JOIN LATERAL generate_series(0, memberships - 1) AS groups(group_id);

-- Documents.  Title prefix, urgency and topic come from independent md5
-- hashes of the id, so the data is fully deterministic.
WITH buckets AS (
    SELECT id,
           (('x' || substr(md5('prefix:' || id), 1, 8))::bit(32)::bigint % 1000) AS prefix_bucket,
           (('x' || substr(md5('suffix:' || id), 1, 8))::bit(32)::bigint % 4) AS suffix_bucket,
           (('x' || substr(md5('display:' || id), 1, 8))::bit(32)::bigint % 64) AS topic
    FROM generate_series(1, 524288) AS ids(id)
)
INSERT INTO public.prefix_doc
SELECT id,
       CASE WHEN id % 173 = 0 THEN NULL ELSE
           CASE WHEN prefix_bucket < 30 THEN 'report-narrow-'
                WHEN prefix_bucket < 120 THEN 'report-broad-'
                WHEN prefix_bucket < 500 THEN 'record-'
                ELSE 'memo-' END ||
           CASE WHEN suffix_bucket = 0 THEN 'urgent-' ELSE 'routine-' END ||
           topic END,
       CASE WHEN id % 257 = 0 THEN NULL ELSE 'secret-' || id END
FROM buckets;
-- Fixed anchor rows (duplicates, NULLs, LIKE escape characters) overwrite
-- ids 1..9.  These in-place UPDATEs move the nine rows to the end of the
-- heap; that placement is part of the fixture.
UPDATE public.prefix_doc SET title = 'report-narrow-urgent-duplicate', secret = 'duplicate-secret' WHERE id IN (1, 2);
UPDATE public.prefix_doc SET title = NULL, secret = 'null-title-secret' WHERE id = 3;
UPDATE public.prefix_doc SET title = 'report-broad-urgent-null', secret = NULL WHERE id = 4;
UPDATE public.prefix_doc SET title = 'report-narrow-urgent-duplicate', secret = 'duplicate-secret' WHERE id = 5;
UPDATE public.prefix_doc SET title = 'report%literal-urgent', secret = 'escaped-percent-secret' WHERE id = 6;
UPDATE public.prefix_doc SET title = 'report_literal-urgent', secret = 'escaped-underscore-secret' WHERE id = 7;
UPDATE public.prefix_doc SET title = E'report\\literal-urgent', secret = 'escaped-backslash-secret' WHERE id = 8;
UPDATE public.prefix_doc SET title = 'report-broad-urgent-null', secret = NULL WHERE id = 9;
-- One ACL row per document, in heap order of prefix_doc.
INSERT INTO public.share_acl
SELECT 'public.prefix_doc', id,
       CASE WHEN id IN (1, 2, 3, 4, 6, 7, 8) THEN 0
            WHEN id IN (5, 9) THEN 999
            ELSE (('x' || substr(md5('acl-group:' || id), 1, 8))::bit(32)::bigint % 1000) END,
       'read'
FROM public.prefix_doc;
-- Two extra ACL rows: a second authorizing group for documents 1 and 2.
INSERT INTO public.share_acl VALUES
    ('public.prefix_doc', 1, 1, 'read'),
    ('public.prefix_doc', 2, 1, 'read');
CREATE INDEX prefix_doc_title_pattern ON public.prefix_doc (title COLLATE "C" text_pattern_ops);
ALTER TABLE public.prefix_doc ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.prefix_doc FORCE ROW LEVEL SECURITY;
CREATE POLICY prefix_sparse ON public.prefix_doc FOR SELECT TO af_prefix_sparse USING (
    EXISTS (
        SELECT 1 FROM public.share_acl s
        JOIN public.group_membership m ON m.group_id = s.group_id
        WHERE m.user_id = 'af_prefix_sparse'
          AND s.relname = 'public.prefix_doc'
          AND s.rid = prefix_doc.id AND s.permission = 'read'
    )
);
CREATE POLICY prefix_medium ON public.prefix_doc FOR SELECT TO af_prefix_medium USING (
    EXISTS (
        SELECT 1 FROM public.share_acl s
        JOIN public.group_membership m ON m.group_id = s.group_id
        WHERE m.user_id = 'af_prefix_medium'
          AND s.relname = 'public.prefix_doc'
          AND s.rid = prefix_doc.id AND s.permission = 'read'
    )
);
CREATE POLICY prefix_dense ON public.prefix_doc FOR SELECT TO af_prefix_dense USING (
    EXISTS (
        SELECT 1 FROM public.share_acl s
        JOIN public.group_membership m ON m.group_id = s.group_id
        WHERE m.user_id = 'af_prefix_dense'
          AND s.relname = 'public.prefix_doc'
          AND s.rid = prefix_doc.id AND s.permission = 'read'
    )
);
-- Audit table written by the logging function that every query calls.
CREATE TABLE public.prefix_audit (
    seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    principal name NOT NULL DEFAULT current_user,
    rid bigint NOT NULL,
    secret text
);
CREATE FUNCTION public.prefix_audit_secret(row_id bigint, value text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    INSERT INTO public.prefix_audit(rid,secret) VALUES (row_id,value);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION public.prefix_audit_secret(bigint,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO af_prefix_sparse, af_prefix_medium, af_prefix_dense;
GRANT SELECT ON public.prefix_doc, public.group_membership, public.share_acl
    TO af_prefix_sparse, af_prefix_medium, af_prefix_dense;
GRANT INSERT ON public.prefix_audit TO af_prefix_sparse, af_prefix_medium, af_prefix_dense;
GRANT USAGE ON SEQUENCE public.prefix_audit_seq_seq TO af_prefix_sparse, af_prefix_medium, af_prefix_dense;
GRANT EXECUTE ON FUNCTION public.prefix_audit_secret(bigint,text) TO af_prefix_sparse, af_prefix_medium, af_prefix_dense;
ANALYZE public.prefix_doc;
ANALYZE public.group_membership;
ANALYZE public.share_acl;
-- One-row metadata table; the stored version label is part of the data.
CREATE TABLE public.prefix_formal_meta (rows bigint NOT NULL, version text NOT NULL);
INSERT INTO public.prefix_formal_meta VALUES (524288, 'formal-grid-r01');

COMMIT;
