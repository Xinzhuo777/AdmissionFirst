-- Cluster-wide login role used for all measured queries: ordinary, direct
-- login, no inheritance, no RLS bypass, no memberships.  Created only if it
-- does not exist; an existing role must have exactly these attributes.
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'caprls_e3_rls_user') THEN
    CREATE ROLE caprls_e3_rls_user LOGIN NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_roles r
      WHERE rolname = 'caprls_e3_rls_user' AND rolcanlogin AND NOT rolsuper
        AND NOT rolinherit AND NOT rolbypassrls AND NOT rolcreaterole
        AND NOT rolcreatedb AND NOT rolreplication
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid)) THEN
    RAISE EXCEPTION 'role caprls_e3_rls_user exists with different attributes or memberships';
  END IF;
END
$role$;
