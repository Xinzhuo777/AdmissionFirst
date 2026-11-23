-- Run once in the private test database. Roles are cluster-local.
BEGIN;

CREATE ROLE af_doc_reader LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE af_doc_other LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT af_doc_other TO af_doc_reader WITH INHERIT FALSE;

CREATE TABLE public.doc (
    id bigint PRIMARY KEY,
    topic integer NOT NULL,
    title text,
    secret text NOT NULL
);
CREATE INDEX doc_topic_id_idx ON public.doc (topic, id);

CREATE TABLE public.group_membership (
    user_id text NOT NULL,
    group_id bigint NOT NULL,
    membership_version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, group_id)
);
CREATE TABLE public.share_acl (
    relname text NOT NULL,
    rid bigint NOT NULL,
    group_id bigint NOT NULL,
    permission text NOT NULL,
    acl_version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (relname, rid, group_id, permission)
);
CREATE INDEX share_acl_lookup_idx
    ON public.share_acl (relname, rid, permission, group_id);
CREATE INDEX share_acl_group_idx
    ON public.share_acl (group_id, relname, permission);

INSERT INTO public.doc (id, topic, title, secret) VALUES
    (1, 7, 'duplicate', 'shared-one'),
    (2, 7, 'duplicate', 'shared-two'),
    (3, 8, 'other-topic', 'shared-other-topic'),
    (4, 7, NULL, 'revoked'),
    (5, 7, 'wrong-permission', 'deny-wrong-permission'),
    (6, 7, NULL, 'newly-granted'),
    (7, 7, 'wrong-relation', 'deny-wrong-relation'),
    (8, 7, 'other-reader', 'deny-other-reader'),
    (9, 7, 'publicly-private', 'deny-no-acl'),
    (10, 7, 'group-switch', 'new-membership');
INSERT INTO public.doc (id, topic, title, secret)
SELECT id, 100 + id % 200, 'filler', 'deny-filler-' || id
FROM generate_series(11, 20000) AS rows(id);

INSERT INTO public.group_membership (user_id, group_id) VALUES
    ('af_doc_reader', 1), ('af_doc_reader', 2), ('af_doc_other', 3);
INSERT INTO public.share_acl (relname, rid, group_id, permission) VALUES
    ('public.doc', 1, 1, 'read'),
    ('public.doc', 1, 2, 'read'),
    ('public.doc', 2, 1, 'read'),
    ('public.doc', 3, 2, 'read'),
    ('public.doc', 4, 1, 'read'),
    ('public.doc', 5, 1, 'write'),
    ('public.different_doc', 7, 1, 'read'),
    ('public.doc', 8, 3, 'read'),
    ('public.doc', 10, 4, 'read');

ALTER TABLE public.doc ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doc FORCE ROW LEVEL SECURITY;
CREATE POLICY doc_reader ON public.doc FOR SELECT TO af_doc_reader
    USING (EXISTS (
        SELECT 1
        FROM public.share_acl AS s
        JOIN public.group_membership AS m ON m.group_id = s.group_id
        WHERE m.user_id = 'af_doc_reader'
          AND s.relname = 'public.doc'
          AND s.rid = doc.id
          AND s.permission = 'read'
    ));
CREATE POLICY doc_other ON public.doc FOR SELECT TO af_doc_other
    USING (EXISTS (
        SELECT 1
        FROM public.share_acl AS s
        JOIN public.group_membership AS m ON m.group_id = s.group_id
        WHERE m.user_id = 'af_doc_other'
          AND s.relname = 'public.doc'
          AND s.rid = doc.id
          AND s.permission = 'read'
    ));
GRANT USAGE ON SCHEMA public TO af_doc_reader, af_doc_other;
GRANT SELECT ON public.doc, public.share_acl, public.group_membership
    TO af_doc_reader, af_doc_other;

-- The user's qualifier reports each actual observation to its own session.
CREATE FUNCTION public.af_doc_audit(bigint, text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
AS $$
BEGIN
    RAISE NOTICE USING MESSAGE =
        'af_doc_observed ' || pg_catalog.json_build_array($1, $2)::text;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION public.af_doc_audit(bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.af_doc_audit(bigint, text)
    TO af_doc_reader, af_doc_other;

ANALYZE public.doc;
ANALYZE public.share_acl;
ANALYZE public.group_membership;

COMMIT;
