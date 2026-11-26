-- Login role, privileges and row-level security policies of the application
-- database, exactly as installed after the data load.  The role is a plain
-- direct login (no superuser, no inheritance, no RLS bypass); it is created
-- here if the cluster does not have it yet.  All three policies describe the
-- request context of principal 90 (tenant 90).
BEGIN;
SET LOCAL search_path = pg_catalog, public;
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'caprls_e10_rls_user') THEN
    CREATE ROLE caprls_e10_rls_user LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'caprls_e10_rls_user'
                 AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
                 AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolinherit)
     OR EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
                WHERE r.rolname = 'caprls_e10_rls_user') THEN
    RAISE EXCEPTION 'application role is not an ordinary direct login';
  END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO caprls_e10_rls_user;
GRANT SELECT ON public.document, public.ticket, public.invoice,
  public.user_account, public.group_membership, public.share_acl, public.purpose_policy TO caprls_e10_rls_user;
GRANT INSERT ON public.udf_audit TO caprls_e10_rls_user;
GRANT USAGE ON SEQUENCE public.udf_audit_call_seq TO caprls_e10_rls_user;
GRANT EXECUTE ON FUNCTION public.unsafe_log(text,text,text,text,bigint,text) TO caprls_e10_rls_user;

ALTER TABLE public.document ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document FORCE ROW LEVEL SECURITY;
CREATE POLICY caprls_e10_policy_document ON public.document
  FOR SELECT TO caprls_e10_rls_user USING ((tenant_id = 90 OR owner_id = 90 OR public = true OR EXISTS (SELECT 1 FROM share_acl a JOIN group_membership gm ON gm.group_id = a.group_id WHERE a.rid = doc_id AND a.relname = 'document' AND gm.user_id = 90 AND a.permission IN ('read','owner') AND TIMESTAMPTZ '2026-06-01 00:00:00+00' BETWEEN a.valid_from AND a.valid_to)));

ALTER TABLE public.invoice ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoice FORCE ROW LEVEL SECURITY;
CREATE POLICY caprls_e10_policy_invoice ON public.invoice
  FOR SELECT TO caprls_e10_rls_user USING ((region = 'region_2' AND EXISTS (SELECT 1 FROM purpose_policy pp WHERE pp.rid = invoice_id AND pp.relname = 'invoice' AND pp.purpose = 'purpose_2' AND pp.allowed = true)));

ALTER TABLE public.ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ticket FORCE ROW LEVEL SECURITY;
CREATE POLICY caprls_e10_policy_ticket ON public.ticket
  FOR SELECT TO caprls_e10_rls_user USING ((tenant_id = 90 OR owner_id = 90));
COMMIT;