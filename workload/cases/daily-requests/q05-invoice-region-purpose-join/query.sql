/* caprls_native_rls_policy_fingerprint: region,purpose */

SELECT count(*)
FROM public.invoice i
JOIN public.user_account u ON u.user_id = i.account_id
WHERE true
  AND i.invoice_id <= 30000
