/* caprls_native_rls_policy_fingerprint: tenant_id,owner_id */

SELECT count(*)
FROM public.ticket t
WHERE true
  AND t.ticket_id BETWEEN 1 AND 100
