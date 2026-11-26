-- Title-search fixture, step 2: run in a new session after
-- title_search_setup.sql has committed.
--
-- 1. Audit state.  The reference database had already served the benchmark
--    queries many times; each run logged audit rows and then emptied the
--    audit table with a plain TRUNCATE (identity NOT restarted).  Reproduce
--    that end state: an empty audit table whose identity sequence stands at
--    28431616, so the next audit row receives seq 28431617.
TRUNCATE public.prefix_audit;
SELECT setval('public.prefix_audit_seq_seq', 28431616, true);

-- 2. Settle the heap.  One sequential read of every table sets the
--    commit hint bits on all tuples and prunes the nine dead row versions
--    left on page 0 of prefix_doc by the anchor UPDATEs (their line pointers
--    become LP_DEAD), which is the page state of the reference database.
--    Row placement (ctid) is not changed by this step.
SET enable_indexscan = off;
SET enable_indexonlyscan = off;
SET enable_bitmapscan = off;
SET max_parallel_workers_per_gather = 0;
SELECT count(*) FROM public.prefix_doc;
SELECT count(*) FROM public.share_acl;
SELECT count(*) FROM public.group_membership;
SELECT count(*) FROM public.prefix_formal_meta;
