ALTER POLICY a027_sparse ON public.a027_document USING (a027_document.id IN (
  SELECT s.rid
  FROM public.a027_share_acl s
  JOIN public.a027_group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'a027_ind_sparse'
    AND s.relname = 'public.a027_document'
    AND s.permission = 'read'
));
