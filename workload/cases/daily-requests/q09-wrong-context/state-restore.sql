BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;

LOCK TABLE public.e10_state_mav_c2732e6953c0fc05 IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.document IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.group_membership IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.artifact_dependencies IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.synthetic_context, public.context_versions IN SHARE MODE;
LOCK TABLE public.base_versions, public.membership_versions
  IN SHARE ROW EXCLUSIVE MODE;




DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.artifact_dependencies
  WHERE artifact_id = 'e10-state:E10_Q9_wrong_context_mav:ctx_000001:c2732e6953c0fc05';
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 9 THEN
    RAISE EXCEPTION 'E10 state dependency cleanup count is not exact';
  END IF;
END;
$$;
DROP TABLE public.e10_state_mav_c2732e6953c0fc05;
COMMIT;
