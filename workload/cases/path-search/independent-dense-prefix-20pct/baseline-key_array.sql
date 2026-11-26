ALTER POLICY a027_dense ON public.a027_document USING (a027_document.id = ANY ((
  SELECT COALESCE(array_agg(s.rid), ARRAY[]::bigint[])
  FROM public.a027_share_acl s
  JOIN public.a027_group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'a027_ind_dense'
    AND s.relname = 'public.a027_document'
    AND s.permission = 'read'
)::bigint[]));
