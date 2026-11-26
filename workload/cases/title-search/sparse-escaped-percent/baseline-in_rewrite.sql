ALTER POLICY prefix_sparse ON public.prefix_doc USING (prefix_doc.id IN (
  SELECT s.rid
  FROM public.share_acl s
  JOIN public.group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'af_prefix_sparse'
    AND s.relname = 'public.prefix_doc'
    AND s.permission = 'read'
));
