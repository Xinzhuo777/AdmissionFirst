SELECT d.doc_id AS rid,
       encode(public.digest(coalesce(d.secret, ''), 'sha256'), 'hex') AS value_hash
FROM public.document d
WHERE (d.tenant_id = 90 OR d.owner_id = 90 OR d.public = true OR EXISTS (SELECT 1 FROM share_acl a JOIN group_membership gm ON gm.group_id = a.group_id WHERE a.rid = d.doc_id AND a.relname = 'document' AND gm.user_id = 90 AND a.permission IN ('read','owner') AND TIMESTAMPTZ '2026-06-01 00:00:00+00' BETWEEN a.valid_from AND a.valid_to)) AND d.doc_id <= 20000
