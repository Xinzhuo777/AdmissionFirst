-- Group-based ACL used by the membership row policies.  One principal
-- ('e3_user', a data value, not a database role) belongs to group 1; group 1
-- may read every customer and every title whose key is a multiple of 10.
-- Fully deterministic: no random numbers, no seeds.
-- The rows are inserted in the physical order of the protected tables.

CREATE TABLE public.group_membership (
  user_id text NOT NULL,
  group_id bigint NOT NULL,
  membership_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, group_id)
);
CREATE TABLE public.share_acl (
  relname text NOT NULL,
  rid bigint NOT NULL,
  group_id bigint NOT NULL,
  permission text NOT NULL,
  acl_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (relname, rid, group_id, permission)
);
INSERT INTO public.group_membership(user_id, group_id, membership_version)
VALUES ('e3_user', 1, 0);
INSERT INTO public.share_acl(relname, rid, group_id, permission, acl_version)
SELECT 'public.tpch_customer', c.c_custkey, 1, 'read', 0
FROM public.tpch_customer c
WHERE (c.c_custkey % 10) = 0
ORDER BY c.ctid;
INSERT INTO public.share_acl(relname, rid, group_id, permission, acl_version)
SELECT 'public.job_title', t.t_id, 1, 'read', 0
FROM public.job_title t
WHERE (t.t_id % 10) = 0
ORDER BY t.ctid;
CREATE INDEX share_acl_lookup_idx ON public.share_acl(relname, rid, permission, group_id);
CREATE INDEX share_acl_group_idx ON public.share_acl(group_id, relname, permission);
ANALYZE public.group_membership;
ANALYZE public.share_acl;
