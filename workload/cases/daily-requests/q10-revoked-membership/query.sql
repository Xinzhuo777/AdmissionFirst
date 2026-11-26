/* caprls_native_rls_policy_fingerprint: tenant_id,owner_id,public */

SELECT count(*)
FROM (
  SELECT d.doc_id
  FROM public.document d
  WHERE true
  ORDER BY d.doc_id
  LIMIT 1000
) q
