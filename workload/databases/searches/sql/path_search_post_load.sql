-- Path-search fixture, step 2: run in a new session after
-- path_search_setup.sql has committed, with no other session open in this
-- database.  VACUUM cannot run inside a transaction block.
--
-- Expected effect: all tuples are frozen and every heap page except page 0
-- of the document table is marked all-visible.  Page 0 keeps eight LP_DEAD
-- line pointers (the old versions of anchor rows 1..8) because VACUUM skips
-- index vacuuming when so few pages carry dead items.
SET default_statistics_target=1000;
VACUUM (FREEZE, ANALYZE) public.a027_document;
VACUUM (FREEZE, ANALYZE) public.a027_share_acl;
VACUUM (FREEZE, ANALYZE) public.a027_group_membership;
