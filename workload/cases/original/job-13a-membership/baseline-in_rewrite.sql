BEGIN;
DO $check$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_roles r WHERE rolname='caprls_e3_rls_user' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid)) THEN RAISE EXCEPTION 'requires original ordinary direct login'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.customer'::regclass AND attname='c_custkey' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped) THEN RAISE EXCEPTION 'requires original BIGINT NOT NULL key public.customer.c_custkey'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.title'::regclass AND attname='id' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped) THEN RAISE EXCEPTION 'requires original BIGINT NOT NULL key public.title.id'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.share_acl'::regclass AND attname='rid' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped) THEN RAISE EXCEPTION 'requires original BIGINT NOT NULL key public.share_acl.rid'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.share_acl'::regclass AND attname='group_id' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped) THEN RAISE EXCEPTION 'requires original BIGINT NOT NULL key public.share_acl.group_id'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.group_membership'::regclass AND attname='group_id' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped) THEN RAISE EXCEPTION 'requires original BIGINT NOT NULL key public.group_membership.group_id'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='a031_expected') THEN RAISE EXCEPTION 'reference schema absent'; END IF;
END $check$;
ALTER TABLE public.customer DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.customer;
CREATE OR REPLACE VIEW a031_expected.customer AS SELECT * FROM public.customer WHERE true;
ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.orders;
CREATE OR REPLACE VIEW a031_expected.orders AS SELECT * FROM public.orders WHERE true;
ALTER TABLE public.lineitem DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.lineitem;
CREATE OR REPLACE VIEW a031_expected.lineitem AS SELECT * FROM public.lineitem WHERE true;
ALTER TABLE public.title DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.title;
CREATE OR REPLACE VIEW a031_expected.title AS SELECT * FROM public.title WHERE EXISTS (SELECT 1 FROM public.share_acl a JOIN public.group_membership m ON m.group_id = a.group_id WHERE a.relname = 'public.title' AND a.rid = title.id AND a.permission = 'read' AND m.user_id = 'e3_user');
CREATE POLICY a031_policy ON public.title FOR SELECT TO caprls_e3_rls_user USING (title.id IN (
  SELECT s.rid
  FROM public.share_acl s
  JOIN public.group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'e3_user'
    AND s.relname = 'public.title'
    AND s.permission = 'read'
));
ALTER TABLE public.title ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.title FORCE ROW LEVEL SECURITY;
COMMIT;
