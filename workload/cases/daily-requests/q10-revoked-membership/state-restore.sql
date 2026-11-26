BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;

LOCK TABLE public.e10_state_mav_035aed1f14d2cbb9 IN ACCESS EXCLUSIVE MODE;
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
  IF (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'E10 membership epoch changed before restoration';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.group_membership
    WHERE user_id = 90 AND group_id = 843
  ) THEN
    RAISE EXCEPTION 'E10 revoked membership unexpectedly reappeared';
  END IF;
  INSERT INTO public.group_membership(user_id, group_id, membership_version)
  VALUES (90, 843, 0);
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership restoration count is not one';
  END IF;
  UPDATE public.membership_versions
  SET version = 0
  WHERE scope_name = 'group_membership'
    AND version = 1;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership epoch restoration count is not one';
  END IF;
END;
$$;

DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.artifact_dependencies
  WHERE artifact_id = 'e10-state:E10_Q10_revoked_membership_mav:ctx_000001:035aed1f14d2cbb9';
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 9 THEN
    RAISE EXCEPTION 'E10 state dependency cleanup count is not exact';
  END IF;
END;
$$;
DROP TABLE public.e10_state_mav_035aed1f14d2cbb9;
COMMIT;
