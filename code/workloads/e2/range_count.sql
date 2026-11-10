-- E2 single-operator range-count workload.
-- The smoke runner binds :lo/:hi and renders the selected authorization
-- template against public.document using doc_id as the RID/key surrogate.
SELECT count(*) AS authorized_range_count
FROM public.document AS d
WHERE d.doc_id BETWEEN :lo AND :hi;
