"""Shared PostgreSQL native RLS setup helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from .postgres_runner import PostgresEnv, run_psql_file


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def run_sql_script(sql: str, pg_env: PostgresEnv) -> str:
    path = _write_temp_sql(sql)
    try:
        return run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)


def configure_native_rls(
    *,
    rel: str,
    policy_name: str,
    predicate: str,
    role_name: str,
    pg_env: PostgresEnv,
) -> None:
    run_sql_script(
        f"""
\\set ON_ERROR_STOP on
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role_name}') THEN
    CREATE ROLE {role_name};
  END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO {role_name};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role_name};
GRANT INSERT ON public.udf_audit TO {role_name};
GRANT USAGE ON SEQUENCE public.udf_audit_call_seq TO {role_name};
GRANT EXECUTE ON FUNCTION public.unsafe_log(text, text, text, text, bigint, text) TO {role_name};
ALTER TABLE {rel} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {rel} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS {policy_name} ON {rel};
CREATE POLICY {policy_name} ON {rel}
  FOR SELECT TO {role_name}
  USING ({predicate});
""",
        pg_env,
    )
