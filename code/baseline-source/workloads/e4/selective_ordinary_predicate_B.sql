-- E4 smoke parent B: leakproof point predicate changes the best parent-aware choice.
SELECT count(*) AS e4_parent_b_rows
FROM public.document AS d
WHERE d.doc_id = :doc_id;
