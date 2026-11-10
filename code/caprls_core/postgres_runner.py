"""PostgreSQL helpers for schema installation and semantic smoke tests."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    POLICY_ENFORCEMENT_ROLE,
)

import hashlib
import json
import math
import os
import platform
import random
import re
import secrets
import selectors
import shlex
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional

from .manifest_validator import file_sha256
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record


class PostgresError(RuntimeError):
    pass


def _render_postgres_error(args: list[str], stdout: str, stderr: str, returncode: int) -> str:
    rendered = " ".join(args)
    detail = (
        f"command failed ({returncode}): {rendered}\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}"
    )
    combined = f"{stdout}\n{stderr}"
    if "could not create shared memory segment" in combined and "shmget" in combined:
        detail += (
            "\nPostgreSQL shared-memory bootstrap failed while allocating a SysV "
            "segment. This is an OS-level shared memory exhaustion condition; "
            "stop stale postgres processes or clear/raise the system SysV shared "
            "memory limits before rerunning live temp-cluster checks."
        )
    return detail


@dataclass(frozen=True)
class PostgresEnv:
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


_SNAPSHOT_TEXT_RE = re.compile(r"^[0-9]+:[0-9]+:[0-9,]*$")
_SESSION_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True)
class PostgresTransactionIdentity:
    """Observed identity of one live PostgreSQL transaction backend.

    This immutable value is evidence about a session, not an execution
    capability and not an AuthorizedExecution object.
    """

    backend_pid: int
    snapshot_text: str
    isolation_level: str
    read_only: bool
    session_nonce: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.backend_pid, int)
            or isinstance(self.backend_pid, bool)
            or self.backend_pid <= 0
        ):
            raise ValueError("transaction backend_pid must be a positive integer")
        if (
            not isinstance(self.snapshot_text, str)
            or _SNAPSHOT_TEXT_RE.fullmatch(self.snapshot_text) is None
        ):
            raise ValueError("transaction snapshot_text is not canonical")
        if self.isolation_level != "repeatable read":
            raise ValueError("transaction isolation_level must be repeatable read")
        if not isinstance(self.read_only, bool):
            raise ValueError("transaction read_only must be boolean")
        if (
            not isinstance(self.session_nonce, str)
            or _SESSION_NONCE_RE.fullmatch(self.session_nonce) is None
        ):
            raise ValueError("transaction session_nonce is not canonical")

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_pid": self.backend_pid,
            "snapshot_text": self.snapshot_text,
            "isolation_level": self.isolation_level,
            "read_only": self.read_only,
            "session_nonce": self.session_nonce,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class SmokeResult:
    test_id: str
    status: str
    details: str


def _run(args: List[str], env: Optional[Mapping[str, str]] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        raise PostgresError(_render_postgres_error(args, proc.stdout, proc.stderr, proc.returncode))
    return proc


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise PostgresError(f"required PostgreSQL tool not found on PATH: {name}")
    return found


_PSQL_ERROR_LINE_RE = re.compile(r"^(?:ERROR|FATAL|PANIC):|^psql:", re.IGNORECASE)
_SQL_TOKEN_AT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ALLOWED_STATEMENT_HEADS = {
    "DELETE",
    "EXPLAIN",
    "INSERT",
    "MERGE",
    "RESET",
    "SELECT",
    "SET",
    "SHOW",
    "UPDATE",
    "VALUES",
    "WITH",
}
_DIRECT_TRANSACTION_CONTROL = {
    "ABORT",
    "BEGIN",
    "COMMIT",
    "END",
    "RELEASE",
    "ROLLBACK",
    "SAVEPOINT",
}


def _validate_single_transaction_statement(sql: str) -> str:
    """Return one conservative SQL statement for the low-level session.

    This is deliberately a finite lexical check, not a general PostgreSQL
    parser. Unknown or ambiguous input is rejected.
    """

    if not isinstance(sql, str) or not sql.strip():
        raise PostgresError("transaction statement must be non-empty SQL")
    if "\x00" in sql or any(
        ord(char) < 32 and char not in "\t\n\r" for char in sql
    ):
        raise PostgresError("transaction statement contains unsupported control bytes")
    semicolon_at: int | None = None
    cursor = 0
    block_depth = 0
    state = "normal"
    dollar_tag = ""
    code_tokens: list[str] = []
    while cursor < len(sql):
        char = sql[cursor]
        following = sql[cursor + 1] if cursor + 1 < len(sql) else ""
        if state == "line_comment":
            if char == "\n":
                state = "normal"
            cursor += 1
            continue
        if state == "block_comment":
            if char == "/" and following == "*":
                block_depth += 1
                cursor += 2
            elif char == "*" and following == "/":
                block_depth -= 1
                cursor += 2
                if block_depth == 0:
                    state = "normal"
            else:
                cursor += 1
            continue
        if state == "single_quote":
            if char == "'" and following == "'":
                cursor += 2
            elif char == "\\" and following:
                cursor += 2
            elif char == "'":
                state = "normal"
                cursor += 1
            else:
                cursor += 1
            continue
        if state == "double_quote":
            if char == '"' and following == '"':
                cursor += 2
            elif char == '"':
                state = "normal"
                cursor += 1
            else:
                cursor += 1
            continue
        if state == "dollar_quote":
            if sql.startswith(dollar_tag, cursor):
                cursor += len(dollar_tag)
                state = "normal"
            else:
                cursor += 1
            continue

        if semicolon_at is not None and not char.isspace():
            if char == "-" and following == "-":
                state = "line_comment"
                cursor += 2
                continue
            if char == "/" and following == "*":
                state = "block_comment"
                block_depth = 1
                cursor += 2
                continue
            raise PostgresError("transaction input is not exactly one SQL statement")
        if char == "-" and following == "-":
            state = "line_comment"
            cursor += 2
        elif char == "/" and following == "*":
            state = "block_comment"
            block_depth = 1
            cursor += 2
        elif char == "'":
            state = "single_quote"
            cursor += 1
        elif char == '"':
            state = "double_quote"
            cursor += 1
        elif char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[cursor:])
            if match is None:
                cursor += 1
            else:
                dollar_tag = match.group(0)
                state = "dollar_quote"
                cursor += len(dollar_tag)
        elif char == ";":
            if semicolon_at is not None:
                raise PostgresError("transaction input is not exactly one SQL statement")
            semicolon_at = cursor
            cursor += 1
        elif char == "\\":
            raise PostgresError(
                "transaction statement cannot contain psql meta directives"
            )
        elif match := _SQL_TOKEN_AT_RE.match(sql, cursor):
            if len(code_tokens) < 8:
                code_tokens.append(match.group(0).upper())
            cursor = match.end()
        else:
            cursor += 1

    if state in {"single_quote", "double_quote", "dollar_quote", "block_comment"}:
        raise PostgresError("transaction statement has an unterminated lexical construct")
    statement = (sql if semicolon_at is None else sql[:semicolon_at]).strip()
    tokens = tuple(code_tokens)
    if not tokens:
        raise PostgresError("transaction statement has no supported SQL head")
    head = tokens[0]
    if head in _DIRECT_TRANSACTION_CONTROL:
        raise PostgresError("caller transaction-control statements are not allowed")
    if head == "START" and len(tokens) > 1 and tokens[1] == "TRANSACTION":
        raise PostgresError("caller transaction-control statements are not allowed")
    if head == "PREPARE" and len(tokens) > 1 and tokens[1] == "TRANSACTION":
        raise PostgresError("caller transaction-control statements are not allowed")
    if head == "SET" and (
        (len(tokens) > 1 and tokens[1] == "TRANSACTION")
        or tokens[:4] == ("SET", "SESSION", "CHARACTERISTICS", "AS")
    ):
        raise PostgresError("caller transaction-control statements are not allowed")
    if head not in _ALLOWED_STATEMENT_HEADS:
        raise PostgresError(f"unsupported transaction statement head: {head}")
    return statement


def _pipe_read_chunk(stream: Any) -> bytes:
    return os.read(stream.fileno(), 4096)


class _PsqlInteractiveChannel:
    """Private marker-framed channel over one persistent psql process."""

    def __init__(self, pg_env: PostgresEnv, *, timeout_s: float = 10.0) -> None:
        timeout = float(timeout_s)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("psql channel timeout_s must be finite and positive")
        psql = _tool("psql")
        try:
            process = subprocess.Popen(
                [
                    psql,
                    "--no-psqlrc",
                    "--no-align",
                    "--tuples-only",
                    "--quiet",
                    "--set",
                    "ON_ERROR_STOP=1",
                    "--set",
                    "VERBOSITY=verbose",
                ],
                env=pg_env.to_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
                shell=False,
            )
        except OSError as exc:
            raise PostgresError(
                f"could not start persistent psql process: {exc}"
            ) from exc
        self._configure(
            process,
            timeout_s=timeout,
            marker_factory=lambda: "__CAPRLS_TXN_" + secrets.token_hex(16) + "__",
            selector_factory=selectors.DefaultSelector,
            read_chunk=_pipe_read_chunk,
        )

    @classmethod
    def _from_process_for_tests(
        cls,
        process: Any,
        *,
        timeout_s: float = 1.0,
        marker_factory: Callable[[], str],
        selector_factory: Callable[[], Any],
        read_chunk: Callable[[Any], bytes],
    ) -> "_PsqlInteractiveChannel":
        channel = cls.__new__(cls)
        channel._configure(
            process,
            timeout_s=timeout_s,
            marker_factory=marker_factory,
            selector_factory=selector_factory,
            read_chunk=read_chunk,
        )
        return channel

    def _configure(
        self,
        process: Any,
        *,
        timeout_s: float,
        marker_factory: Callable[[], str],
        selector_factory: Callable[[], Any],
        read_chunk: Callable[[Any], bytes],
    ) -> None:
        timeout = float(timeout_s)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("psql channel timeout_s must be finite and positive")
        if process.stdin is None or process.stdout is None:
            raise PostgresError("persistent psql process lacks stdin/stdout pipes")
        self._process = process
        self._timeout_s = timeout
        self._marker_factory = marker_factory
        self._selector_factory = selector_factory
        self._read_chunk = read_chunk
        self._read_buffer = b""
        self._closed = False
        self._broken = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def broken(self) -> bool:
        return self._broken

    def execute(self, sql: str) -> str:
        if self._closed or self._broken:
            raise PostgresError("persistent psql channel is not usable")
        if not isinstance(sql, str) or not sql.strip():
            raise PostgresError("persistent psql channel requires non-empty SQL")
        try:
            marker = self._marker_factory()
        except Exception as exc:
            self._fail(
                "persistent psql marker generation failed",
                cause=exc,
            )
        if not isinstance(marker, str) or re.fullmatch(r"[A-Za-z0-9_]+", marker) is None:
            self._fail("persistent psql marker factory returned an invalid marker")
        payload = (sql.rstrip() + "\n\\echo " + marker + "\n").encode("utf-8")
        self._write_all(payload)
        return self._read_until_marker(marker)

    def _write_all(self, payload: bytes) -> None:
        offset = 0
        payload_size = len(payload)
        while offset < payload_size:
            remaining = payload_size - offset
            try:
                written = self._process.stdin.write(payload[offset:])
            except Exception as exc:
                self._fail("persistent psql write failed", cause=exc)
            if (
                not isinstance(written, int)
                or isinstance(written, bool)
                or written <= 0
                or written > remaining
            ):
                self._fail(
                    "persistent psql write returned an invalid byte count: "
                    f"{written!r}"
                )
            offset += written
        try:
            self._process.stdin.flush()
        except Exception as exc:
            self._fail("persistent psql flush failed", cause=exc)

    def _read_until_marker(self, marker: str) -> str:
        deadline = time.monotonic() + self._timeout_s
        output: list[str] = []
        try:
            selector = self._selector_factory()
        except Exception as exc:
            self._fail(
                "persistent psql selector creation failed",
                cause=exc,
            )
        try:
            try:
                selector.register(self._process.stdout, selectors.EVENT_READ)
            except Exception as exc:
                self._fail(
                    "persistent psql selector registration failed",
                    cause=exc,
                )
            while True:
                while b"\n" in self._read_buffer:
                    raw_line, self._read_buffer = self._read_buffer.split(b"\n", 1)
                    line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
                    if line == marker:
                        return "\n".join(output).strip()
                    output.append(line)
                    if _PSQL_ERROR_LINE_RE.match(line.strip()):
                        self._fail(
                            "persistent psql reported a PostgreSQL error:\n"
                            + "\n".join(output)
                        )
                returncode = self._process.poll()
                if returncode is not None:
                    detail = "\n".join(output)
                    self._fail(
                        f"persistent psql exited before marker ({returncode}):\n{detail}"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail(
                        "persistent psql statement timed out before marker:\n"
                        + "\n".join(output)
                    )
                try:
                    events = selector.select(remaining)
                except Exception as exc:
                    self._fail(
                        "persistent psql selector wait failed",
                        cause=exc,
                    )
                if not events:
                    self._fail(
                        "persistent psql statement timed out before marker:\n"
                        + "\n".join(output)
                    )
                try:
                    chunk = self._read_chunk(self._process.stdout)
                except (OSError, ValueError) as exc:
                    self._fail(f"persistent psql read failed: {exc}")
                if not chunk:
                    tail = self._read_buffer.rstrip(b"\r").decode(
                        "utf-8", errors="replace"
                    )
                    if tail:
                        if tail == marker:
                            self._read_buffer = b""
                            return "\n".join(output).strip()
                        output.append(tail)
                    returncode = self._process.poll()
                    self._fail(
                        "persistent psql reached EOF before marker"
                        + (
                            ""
                            if returncode is None
                            else f" (returncode {returncode})"
                        )
                        + ":\n"
                        + "\n".join(output)
                    )
                self._read_buffer += chunk
        finally:
            try:
                selector.close()
            except Exception:
                pass

    def _fail(self, message: str, *, cause: Exception | None = None) -> None:
        self._broken = True
        self._shutdown(force=True)
        error = PostgresError(message)
        if cause is None:
            raise error
        raise error from cause

    def _shutdown(self, *, force: bool) -> None:
        if self._closed:
            return
        self._closed = True
        process = self._process
        if process.poll() is None and not force:
            try:
                process.stdin.write(b"\\q\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                force = True
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=min(self._timeout_s, 1.0))
            except subprocess.TimeoutExpired:
                force = True
        if process.poll() is None and force:
            try:
                process.terminate()
                process.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        self._shutdown(force=self._broken)


def _free_port() -> int:
    # The sandbox can disallow probe binds. PostgreSQL is started with
    # listen_addresses='' below, so this port only names the private Unix socket.
    return random.randint(20000, 60000)


def _temporary_cluster_postgres_options(port: int, socket_dir: Path) -> str:
    """Return conservative postgres options for short-lived test clusters."""

    gucs = {
        "listen_addresses": "",
        "shared_buffers": os.environ.get("CAPRLS_PG_SHARED_BUFFERS", "16MB"),
        "max_connections": os.environ.get("CAPRLS_PG_MAX_CONNECTIONS", "10"),
        "autovacuum": "off",
        "jit": "off",
        "max_worker_processes": "1",
        "max_parallel_workers": "0",
        "max_parallel_workers_per_gather": "0",
    }
    parts = ["-p", str(port), "-k", str(socket_dir)]
    for key, value in gucs.items():
        parts.extend(["-c", f"{key}={value}"])
    extra_options = os.environ.get("CAPRLS_PG_EXTRA_OPTS")
    if extra_options:
        parts.extend(shlex.split(extra_options))
    return shlex.join(parts)


def _temporary_cluster_initdb_args(
    initdb: str,
    data_dir: Path,
    *,
    user: str = "postgres",
) -> list[str]:
    shared_memory_type = os.environ.get("CAPRLS_PG_SHARED_MEMORY_TYPE", "mmap")
    dynamic_shared_memory_type = os.environ.get("CAPRLS_PG_DYNAMIC_SHARED_MEMORY_TYPE", "posix")
    shared_buffers = os.environ.get("CAPRLS_PG_INITDB_SHARED_BUFFERS", "400kB")
    max_connections = os.environ.get("CAPRLS_PG_INITDB_MAX_CONNECTIONS", "20")
    return [
        initdb,
        "-A",
        "trust",
        "-U",
        user,
        "--encoding=UTF8",
        "--no-locale",
        "-c",
        f"shared_memory_type={shared_memory_type}",
        "-c",
        f"dynamic_shared_memory_type={dynamic_shared_memory_type}",
        "-c",
        f"shared_buffers={shared_buffers}",
        "-c",
        f"max_connections={max_connections}",
        "-D",
        str(data_dir),
    ]


@contextmanager
def temporary_cluster(database: str = "caprls_smoke") -> Iterator[PostgresEnv]:
    """Start an isolated temporary PostgreSQL cluster and stop it on exit."""

    initdb = _tool("initdb")
    pg_ctl = _tool("pg_ctl")
    createdb = _tool("createdb")
    tmp_parent = Path(os.environ.get("CAPRLS_TMPDIR", "/private/tmp"))
    with tempfile.TemporaryDirectory(prefix="caprls_pg_", dir=str(tmp_parent)) as tmp:
        root = Path(tmp)
        data_dir = root / "data"
        socket_dir = root / "socket"
        socket_dir.mkdir()
        log_path = root / "postgres.log"
        port = _free_port()

        _run(_temporary_cluster_initdb_args(initdb, data_dir))
        _run(
            [
                pg_ctl,
                "-D",
                str(data_dir),
                "-o",
                _temporary_cluster_postgres_options(port, socket_dir),
                "-l",
                str(log_path),
                "start",
                "-w",
            ]
        )

        env = PostgresEnv(
            host=str(socket_dir),
            port=port,
            user="postgres",
            database=database,
        )
        try:
            _run([createdb, database], env=env.to_env())
            yield env
        finally:
            try:
                _run([pg_ctl, "-D", str(data_dir), "stop", "-m", "fast", "-w"])
            except PostgresError:
                _run([pg_ctl, "-D", str(data_dir), "stop", "-m", "immediate", "-w"])


def run_psql_file(
    sql_path: Path,
    pg_env: PostgresEnv,
    variables: Mapping[str, str] | None = None,
) -> str:
    psql = _tool("psql")
    args = [
        psql,
        "--no-align",
        "--tuples-only",
        "--set",
        "ON_ERROR_STOP=1",
    ]
    for key, value in sorted((variables or {}).items()):
        args.extend(["--set", f"{key}={value}"])
    args.extend(["--file", str(sql_path)])
    proc = _run(
        args,
        env=pg_env.to_env(),
    )
    return str(proc.stdout)


def run_psql_command(sql: str, pg_env: PostgresEnv) -> str:
    psql = _tool("psql")
    proc = _run(
        [
            psql,
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


_TRANSACTION_IDENTITY_SQL = """
SELECT json_build_object(
  'backend_pid', pg_backend_pid(),
  'snapshot_text', pg_current_snapshot()::text,
  'isolation_level', current_setting('transaction_isolation'),
  'read_only', current_setting('transaction_read_only')::boolean
)::text;
""".strip()

_E8B_DIRECT_ROWS_JSON_LINES_WRAPPER_VERSION = 1
_E8B_DIRECT_ROWS_JSON_LINES_TRANSPORT_SEMANTICS = (
    "e8b_direct_raw_json_array_lines_transport_v1"
)


def _render_e8b_direct_rows_once_as_json_lines(
    sql: str,
) -> tuple[str, str]:
    """Return the normalized finite source and its fixed one-shot wrapper."""

    statement = _validate_single_transaction_statement(sql)
    head = _SQL_TOKEN_AT_RE.match(statement)
    if head is None or head.group(0).upper() != "SELECT":
        raise PostgresError(
            "E8b direct row transport requires a SELECT-headed statement"
        )
    wrapped_statement = _validate_single_transaction_statement(
        "WITH caprls_e8b_direct_source AS MATERIALIZED (\n"
        + statement
        + "\n)\n"
        "SELECT pg_catalog.jsonb_build_array(\n"
        "  caprls_e8b_direct_source.doc_id,\n"
        "  caprls_e8b_direct_source.tenant_id,\n"
        "  caprls_e8b_direct_source.region\n"
        ")::pg_catalog.text\n"
        "FROM caprls_e8b_direct_source"
    )
    return statement, wrapped_statement + "\n;"


class PostgresTransactionSession:
    """Low-level same-backend transaction infrastructure.

    This class is not an AuthorizedExecution runner. It accepts only one
    conservatively checked SQL statement at a time and does not accept an
    AuthorizedExecution object, a certificate, or caller-provided identity as
    execution permission.
    """

    def __init__(
        self,
        pg_env: PostgresEnv,
        *,
        read_only: bool = False,
        statement_timeout_s: float = 10.0,
    ) -> None:
        if not isinstance(read_only, bool):
            raise ValueError("transaction read_only declaration must be boolean")
        channel = _PsqlInteractiveChannel(
            pg_env,
            timeout_s=statement_timeout_s,
        )
        self._initialize(
            channel,
            read_only=read_only,
            session_nonce=secrets.token_hex(16),
        )

    @classmethod
    def _from_channel_for_tests(
        cls,
        channel: Any,
        *,
        read_only: bool = False,
        session_nonce: str | None = None,
    ) -> "PostgresTransactionSession":
        """Private test seam; production construction always starts psql."""

        session = cls.__new__(cls)
        session._initialize(
            channel,
            read_only=read_only,
            session_nonce=session_nonce or secrets.token_hex(16),
        )
        return session

    def _initialize(
        self,
        channel: Any,
        *,
        read_only: bool,
        session_nonce: str,
    ) -> None:
        if not isinstance(read_only, bool):
            raise ValueError("transaction read_only declaration must be boolean")
        if not hasattr(channel, "execute") or not hasattr(channel, "close"):
            raise TypeError("transaction channel does not implement execute/close")
        if _SESSION_NONCE_RE.fullmatch(str(session_nonce)) is None:
            raise ValueError("transaction session nonce is invalid")
        self._channel = channel
        self._declared_read_only = read_only
        self._session_nonce = str(session_nonce)
        self._state = "starting"
        self._identity: PostgresTransactionIdentity | None = None
        self._active_capability: object | None = object()
        begin = (
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;"
            if read_only
            else "BEGIN ISOLATION LEVEL REPEATABLE READ READ WRITE;"
        )
        try:
            channel.execute(begin)
            identity = self._observe_identity()
            if identity.read_only is not read_only:
                raise PostgresError(
                    "transaction read-only identity does not match declaration"
                )
        except Exception as exc:
            self._state = "failed"
            self._active_capability = None
            try:
                channel.close()
            except Exception:
                pass
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError("transaction channel initialization failed") from exc
        self._identity = identity
        self._state = "active"

    @property
    def state(self) -> str:
        return self._state

    @property
    def identity(self) -> PostgresTransactionIdentity:
        if self._identity is None:
            raise PostgresError("transaction identity is unavailable")
        return self._identity

    def _observe_identity(self) -> PostgresTransactionIdentity:
        output = self._channel.execute(_TRANSACTION_IDENTITY_SQL)
        payload: Mapping[str, Any] | None = None
        for line in reversed(output.splitlines()):
            candidate = line.strip()
            if not candidate.startswith("{") or not candidate.endswith("}"):
                continue
            try:
                raw = json.loads(candidate)
            except json.JSONDecodeError as exc:
                raise PostgresError(
                    "transaction identity query returned malformed JSON"
                ) from exc
            if isinstance(raw, Mapping):
                payload = raw
                break
        expected_keys = {
            "backend_pid",
            "snapshot_text",
            "isolation_level",
            "read_only",
        }
        if payload is None or set(payload) != expected_keys:
            raise PostgresError("transaction identity query returned incomplete facts")
        try:
            return PostgresTransactionIdentity(
                backend_pid=payload["backend_pid"],
                snapshot_text=payload["snapshot_text"],
                isolation_level=payload["isolation_level"],
                read_only=payload["read_only"],
                session_nonce=self._session_nonce,
            )
        except (TypeError, ValueError) as exc:
            raise PostgresError(f"transaction identity facts are invalid: {exc}") from exc

    def _require_active(self) -> None:
        if self._state != "active" or self._active_capability is None:
            raise PostgresError(
                f"transaction session is not active: {self._state}"
            )

    def _invalidate(self, message: str) -> None:
        self._state = "failed"
        self._active_capability = None
        try:
            self._channel.close()
        except Exception:
            pass
        raise PostgresError(message)

    def _record_channel_failure(self) -> None:
        self._state = "failed"
        self._active_capability = None
        try:
            self._channel.close()
        except Exception:
            pass

    def execute(self, sql: str) -> str:
        """Execute one low-level statement; not an authorization transition."""

        self._require_active()
        statement = _validate_single_transaction_statement(sql)
        try:
            return self._channel.execute(statement + "\n;")
        except Exception as exc:
            self._record_channel_failure()
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError("transaction channel statement failed") from exc

    def _describe_result_columns_without_execution(self, sql: str) -> str:
        """Return one private low-level psql result description without a body run.

        The raw description is not a typed observation, execution permission,
        result evidence, or a result verdict. This method does not execute the
        query body and is only an adapter-internal primitive.
        """

        self._require_active()
        statement = _validate_single_transaction_statement(sql)
        head = _SQL_TOKEN_AT_RE.match(statement)
        if head is None or head.group(0).upper() != "SELECT":
            raise PostgresError(
                "result description requires a SELECT-headed statement"
            )
        try:
            return self._channel.execute(statement + "\n\\gdesc")
        except Exception as exc:
            self._record_channel_failure()
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError(
                "transaction channel result description failed"
            ) from exc

    def _execute_e8b_direct_rows_once_as_json_lines(self, sql: str) -> str:
        """Return lossless raw transport for one finite E8b direct SELECT.

        The fixed nonempty JSON-array envelope preserves row occurrences and
        channel order while protecting text values from line/marker framing.
        This private primitive returns only raw adapter transport.  It is not
        typed rows, canonical normalization, a schema observation,
        ResultEvidence, an equality verdict, TraceObs, or a production API.
        """

        self._require_active()
        _statement, wrapped_statement = (
            _render_e8b_direct_rows_once_as_json_lines(sql)
        )
        try:
            return self._channel.execute(wrapped_statement)
        except Exception as exc:
            self._record_channel_failure()
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError(
                "E8b direct row transport statement failed"
            ) from exc

    def recheck_identity(self) -> PostgresTransactionIdentity:
        """Re-observe backend/snapshot facts and reject any identity drift."""

        self._require_active()
        try:
            observed = self._observe_identity()
        except Exception as exc:
            self._record_channel_failure()
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError("transaction channel identity check failed") from exc
        if observed != self.identity:
            self._invalidate("transaction backend or snapshot identity changed")
        return observed

    def _finish(self, statement: str, terminal_state: str) -> None:
        self._require_active()
        try:
            self._channel.execute(statement)
            self._channel.close()
        except Exception as exc:
            self._record_channel_failure()
            if isinstance(exc, PostgresError):
                raise
            raise PostgresError("transaction channel terminal statement failed") from exc
        self._state = terminal_state
        self._active_capability = None

    def commit(self) -> None:
        self._finish("COMMIT;", "committed")

    def rollback(self) -> None:
        self._finish("ROLLBACK;", "rolled_back")

    def close(self) -> None:
        if self._state == "active":
            self.rollback()
            return
        try:
            self._channel.close()
        except Exception:
            pass

    def __enter__(self) -> "PostgresTransactionSession":
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if self._state == "active":
            try:
                self.rollback()
            except PostgresError:
                if exc_type is None:
                    raise
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def init_db(root: Path, pg_env: PostgresEnv) -> None:
    run_psql_file(root / "sql" / "schema" / "000_core.sql", pg_env)


def _parse_smoke_json(stdout: str) -> List[SmokeResult]:
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            payload = stripped
    if not payload:
        raise PostgresError(f"semantic smoke SQL did not emit JSON results:\n{stdout}")
    raw = json.loads(payload)
    return [
        SmokeResult(
            test_id=str(item["test_id"]),
            status=str(item["status"]),
            details=str(item.get("details") or ""),
        )
        for item in raw
    ]


def _git_commit(root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip()


def _raw_result_record(
    root: Path,
    result: SmokeResult,
    manifest_hash: str,
    elapsed_ms: float,
    pg_version: str,
) -> Dict[str, Any]:
    passed = result.status == "pass"
    status = "pass" if passed else "wrong_result"
    test_id = result.test_id
    udf_calls = {
        "PG_RLS_nonleakproof_order": 2,
        "PG_security_barrier_nonleakproof": 1,
        "PG_volatile_audit_call": 1,
    }.get(test_id, 0)
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"PG_SMOKE_{test_id}",
        "manifest_id": "pg_semantic_smoke_v1",
        "manifest_hash": manifest_hash,
        "experiment": "PG_SMOKE",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": "postgres_semantics", "scale": "single_session", "seed": 0},
        "query": {
            "query_id": test_id,
            "path": "sql/smoke/postgres_semantics.sql",
            "params": {},
        },
        "policy": {
            "policy_id": "postgres_semantic_policy",
            "policy_version": 0,
            "policy_sql_manifest_hash": manifest_hash,
        },
        "context": {
            "context_id": "pg_semantic_smoke",
            "ctx_hash": manifest_hash,
        },
        "mode": _mode_for_smoke_test(test_id),
        "template": {
            "template_id": "postgres_semantic_smoke_v1",
            "alternative": "PostgreSQLSemanticSmoke",
        },
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "semantic_smoke_not_template_candidate",
        },
        "evaluation_role": POLICY_ENFORCEMENT_ROLE,
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {},
            "membership": {},
            "context": {},
            "trusted_state": {"schema": 1},
            "base": {},
            "artifacts": {},
        },
        "planner": {
            "level": "semantic-smoke",
            "planning_time_ms": 0.0,
            "generated_templates": 0,
            "rejected_templates": 0,
            "costed_templates": 0,
            "rejection_reasons": {},
            "chosen_estimated_cost": 0.0,
            "chosen_rank_vs_template_oracle": None,
            "local_feature_vector": None,
            "parent_requirement_vector": None,
            "candidates": [],
            "disabled_components": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": "pass" if passed else "fail",
            "plan_hash": manifest_hash,
            "explain_path": None,
            "reasons": [] if passed else [result.details],
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": "execute",
            "expected_action": "execute",
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": "pass" if passed else "fail",
            "audit_path": None,
            "udf_calls": udf_calls,
            "unauthorized_observations": 0 if passed else 1,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": {
            "emitted_sql_path": "sql/smoke/postgres_semantics.sql",
            "emitted_sql_hash": manifest_hash,
            "normalized_sql_hash": manifest_hash,
        },
        "oracle_check": {
            "status": "match" if passed else "mismatch",
            "oracle_kind": "postgres_semantic_smoke",
            "set_diff_left": 0 if passed else 1,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": elapsed_ms,
            "verification": 0.0,
            "total": elapsed_ms,
        },
        "result": {
            "row_count": 1,
            "result_hash": manifest_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": 0,
            "residual_checks": 0,
            "candidate_rows": 0,
            "authorized_rows": 0,
            "artifact_lookups": 0,
            "base_fetches": 0,
        },
        "artifact_cost": {
            "query_only_ms": elapsed_ms,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "status": status,
        "failure": None if passed else {"reason": result.details},
    }


def _mode_for_smoke_test(test_id: str) -> str:
    if "security_barrier" in test_id:
        return "security-barrier"
    if "RLS" in test_id:
        return "native-pg-rls"
    return ADMISSION_FIRST_MODE


def write_raw_results(
    root: Path,
    results: Iterable[SmokeResult],
    output_dir: Path,
    manifest_hash: str,
    elapsed_ms: float,
    pg_version: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for result in results:
        record = _raw_result_record(root, result, manifest_hash, elapsed_ms, pg_version)
        issues = validate_raw_run_record(record)
        if issues:
            rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
            raise PostgresError(f"generated raw result failed schema validation: {rendered}")
        target = output_dir / f"{result.test_id}.json"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_semantic_smoke(root: Path, pg_env: PostgresEnv, output_dir: Optional[Path]) -> List[SmokeResult]:
    init_db(root, pg_env)
    sql_path = root / "sql" / "smoke" / "postgres_semantics.sql"
    manifest_hash = file_sha256(sql_path)
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    started = time.monotonic()
    stdout = run_psql_file(sql_path, pg_env)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    results = _parse_smoke_json(stdout)
    if output_dir is not None:
        write_raw_results(root, results, output_dir, manifest_hash, elapsed_ms, pg_version)
    return results
