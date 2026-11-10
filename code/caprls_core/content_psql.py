"""PostgreSQL executor for content-boundary checks."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

EXECUTOR_ID = "private_duplicated_v1"

#: Statement heads this executor is willing to send.  The content package never
#: writes to a protected relation; DDL is limited to ``CREATE TEMP TABLE``.
_ALLOWED_HEADS = frozenset(
    {
        "BEGIN",
        "COMMIT",
        "CREATE",
        "ROLLBACK",
        "SELECT",
        "SET",
        "SHOW",
        "WITH",
    }
)

_ERROR_LINE_RE = re.compile(r"^(?:ERROR|FATAL|PANIC):|^psql:", re.IGNORECASE)
_SNAPSHOT_TEXT_RE = re.compile(r"^[0-9]+:[0-9]+:[0-9,]*$")


class ContentPsqlError(RuntimeError):
    """Any failure of the private executor.  Always fail-closed."""


@dataclass(frozen=True)
class ContentPostgresEnv:
    """Connection coordinates for the private executor.

    Deliberately equivalent in shape to ``postgres_runner.PostgresEnv`` but a
    separate type, so no measurement-path object can be passed in by accident.
    """

    host: str
    port: int
    user: str
    database: str

    def to_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "PGHOST": self.host,
                "PGPORT": str(self.port),
                "PGUSER": self.user,
                "PGDATABASE": self.database,
            }
        )
        return env

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "database": self.database,
        }

    @classmethod
    def from_environment(cls) -> "ContentPostgresEnv":
        """Build the connection from ``PGHOST``/``PGPORT``/``PGUSER``/``PGDATABASE``."""

        host = os.environ.get("PGHOST")
        database = os.environ.get("PGDATABASE")
        if not host or not database:
            raise ContentPsqlError(
                "content executor requires PGHOST and PGDATABASE in the environment"
            )
        raw_port = os.environ.get("PGPORT", "5432")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ContentPsqlError(f"PGPORT is not an integer: {raw_port!r}") from exc
        user = os.environ.get("PGUSER") or os.environ.get("USER") or "postgres"
        return cls(host=host, port=port, user=user, database=database)


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ContentPsqlError(f"required PostgreSQL tool not found on PATH: {name}")
    return found


def _render_failure(
    args: Sequence[str], stdout: str, stderr: str, returncode: int
) -> str:
    return (
        "content psql command failed ({code}): {cmd}\nstdout:\n{out}\nstderr:\n{err}".format(
            code=returncode,
            cmd=" ".join(args),
            out=stdout,
            err=stderr,
        )
    )


def _invoke(
    args: List[str], env: Optional[Mapping[str, str]] = None
) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        raise ContentPsqlError(
            _render_failure(args, proc.stdout, proc.stderr, proc.returncode)
        )
    combined = "{}\n{}".format(proc.stdout, proc.stderr)
    for line in combined.splitlines():
        if _ERROR_LINE_RE.match(line.strip()):
            raise ContentPsqlError(
                _render_failure(args, proc.stdout, proc.stderr, proc.returncode)
            )
    return proc


def validate_statement_head(sql: str) -> str:
    """Reject anything this package has no business sending."""

    stripped = sql.strip()
    if not stripped:
        raise ContentPsqlError("content executor received an empty statement")
    head = re.match(r"[A-Za-z_][A-Za-z0-9_]*", stripped)
    if head is None or head.group(0).upper() not in _ALLOWED_HEADS:
        raise ContentPsqlError(
            "content executor rejects statement head: " + stripped[:40]
        )
    return stripped


def run_command(sql: str, pg_env: ContentPostgresEnv) -> str:
    """Run one ``--command`` payload and return stripped stdout."""

    validate_statement_head(sql)
    psql = _tool("psql")
    proc = _invoke(
        [
            psql,
            "--quiet",
            "--no-align",
            "--tuples-only",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            sql,
        ],
        env=pg_env.to_env(),
    )
    return str(proc.stdout).strip()


def run_script(sql: str, pg_env: ContentPostgresEnv) -> str:
    """Run a multi-statement script through ``--file`` and return raw stdout.

    Used for the single-transaction protocol of §8.1, which must keep every
    statement in one backend session.
    """

    validate_statement_head(sql)
    psql = _tool("psql")
    import tempfile

    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".sql", delete=False
    )
    try:
        with handle:
            handle.write(sql)
        proc = _invoke(
            [
                psql,
                # F7 belt: `--quiet` suppresses psql's per-statement command
                # status (`SELECT 6` for CREATE TABLE AS, `SET`, `BEGIN`, …).
                # The braces are in the parser, which classifies any such line
                # as noise and refuses on anything it does not recognise, so a
                # psql that ignored this flag could no longer corrupt a value.
                "--quiet",
                "--no-align",
                "--tuples-only",
                "--set",
                "ON_ERROR_STOP=1",
                "--file",
                handle.name,
            ],
            env=pg_env.to_env(),
        )
        return str(proc.stdout)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:  # pragma: no cover - best effort
            pass


def run_scalar(sql: str, pg_env: ContentPostgresEnv) -> str:
    """Run a statement expected to return exactly one scalar."""

    raw = run_command(sql, pg_env)
    lines = [line for line in raw.splitlines() if line.strip() != ""]
    if len(lines) != 1:
        raise ContentPsqlError(
            "content executor expected one scalar row, got {}".format(len(lines))
        )
    return lines[0]


def quote_literal(value: object) -> str:
    """SQL string literal with doubled single quotes."""

    return "'" + str(value).replace("'", "''") + "'"


def quote_ident(value: str) -> str:
    if re.fullmatch(r"[a-z_][a-z0-9_]*", value) is None:
        raise ContentPsqlError(f"unsafe SQL identifier: {value!r}")
    return value


def assert_snapshot_token(token: str) -> str:
    if _SNAPSHOT_TEXT_RE.fullmatch(token.strip()) is None:
        raise ContentPsqlError(f"snapshot token is not canonical: {token!r}")
    return token.strip()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def executor_identity() -> Dict[str, str]:
    return {
        "executor": EXECUTOR_ID,
        "executor_digest": file_digest(Path(__file__)),
        "postgres_runner_touched": "false",
    }
