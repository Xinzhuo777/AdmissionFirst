/* caprls_native_rls_policy_fingerprint: tenant_id,owner_id,public */

SELECT count(*)
FROM public.document d
WHERE true
  AND d.doc_id <= 50000
