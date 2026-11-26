BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;

LOCK TABLE public.e10_state_mav_fa7631907e699336 IN ACCESS EXCLUSIVE MODE;
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
  IF (SELECT version FROM public.base_versions WHERE relname = 'document')
     IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'E10 base epoch changed before restoration';
  END IF;
  IF (
    SELECT document.payload
    FROM public.document document
    WHERE document.doc_id = 1
  ) IS DISTINCT FROM '{"bucket":1,"caprls_state_epoch":"sha256:5c139e11c2e42e62841086538a7eda82fccbf0878abc5cb5e04c364cf3b25a4d","doc_id":1,"seed":52}'::jsonb THEN
    RAISE EXCEPTION 'E10 base payload changed before restoration';
  END IF;
  UPDATE public.document
  SET payload = '{"bucket":1,"doc_id":1,"seed":52}'::jsonb
  WHERE doc_id = 1;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base restoration count is not one';
  END IF;
  UPDATE public.base_versions
  SET version = 0
  WHERE relname = 'document'
    AND version = 1;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch restoration count is not one';
  END IF;
END;
$$;

DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.artifact_dependencies
  WHERE artifact_id = 'e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336';
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 9 THEN
    RAISE EXCEPTION 'E10 state dependency cleanup count is not exact';
  END IF;
END;
$$;
DROP TABLE public.e10_state_mav_fa7631907e699336;
COMMIT;
