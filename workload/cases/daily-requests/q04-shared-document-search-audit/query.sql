/* caprls_native_rls_policy_fingerprint: tenant_id,owner_id,public */

WITH auth AS MATERIALIZED (
  SELECT d.doc_id AS rid, d.doc_id AS __rid, d.secret
  FROM public.document d
  WHERE true
    AND d.doc_id <= 20000
)
SELECT count(*)
FROM auth d
WHERE public.unsafe_log('e10', 'E10_Q4_shared_document_search_audit', 'barrier_exact', 'case_occ_1', d.rid, d.secret)
