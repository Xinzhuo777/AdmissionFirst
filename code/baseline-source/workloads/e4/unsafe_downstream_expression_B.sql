-- E4 smoke parent B: an immediate unsafe expression forces early exact authorization.
SELECT count(*) AS e4_unsafe_parent_rows
FROM public.document AS d;
