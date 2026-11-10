-- E5 controlled fixed-representation witness smoke.
-- The runner renders the witness policy/template and binds the selected
-- artifact configuration for each fixed baseline mode.
SELECT count(*) AS e5_authorized_rows
FROM public.document AS d
WHERE d.doc_id BETWEEN :lo AND :hi;
