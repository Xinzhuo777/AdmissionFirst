"""Server-time adapter for the second unified CAPRLS measurement activity.

The measured statement is the supplied complete SQL, not a count wrapper.
EXPLAIN ANALYZE executes it once; correctness/result comparison belongs to a
separate untimed call.  Session preparation, psql transport and transaction
shutdown are not included in the PostgreSQL planning/execution metric.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from collections.abc import Mapping
from typing import Any

from .postgres_runner import (
    PostgresEnv,
    PostgresError,
    PostgresTransactionSession,
    _PsqlInteractiveChannel,
    _validate_single_transaction_statement,
)


EXPLAIN_PREFIX = "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) "
SERVER_TIME_SCOPE = (
    "postgres_complete_sql_planning_execution_plus_same_transaction_validation"
)
_ROLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_RUNTIME_SQL = """
SELECT pg_catalog.json_build_object(
  'current_user', current_user,
  'session_user', session_user,
  'row_security', pg_catalog.current_setting('row_security'),
  'isolation_level', pg_catalog.current_setting('transaction_isolation'),
  'transaction_read_only', pg_catalog.current_setting('transaction_read_only'),
  'work_mem', pg_catalog.current_setting('work_mem'),
  'shared_buffers', pg_catalog.current_setting('shared_buffers')
)::text
""".strip()


class _BorrowedChannel:
    """Transaction-scoped view: COMMIT must not close the owned backend."""
    def __init__(self, backend: "PersistentServerTimingBackend"):
        self.backend = backend

    def execute(self, sql: str) -> str:
        if self.backend.closed:
            raise PostgresError("persistent server timing backend is closed")
        return self.backend._channel.execute(sql)

    def close(self) -> None:
        # The backend owner closes the real channel.  Transaction failures
        # invalidate it through run_server_timed_sql's exception path.
        pass


class _PersistentTransactionSession(PostgresTransactionSession):
    def __init__(self, backend: "PersistentServerTimingBackend", *, read_only: bool):
        # A production channel created by _PsqlInteractiveChannel, not the
        # private test constructor.  Every member gets a new RR transaction.
        self._initialize(
            _BorrowedChannel(backend), read_only=read_only,
            session_nonce=secrets.token_hex(16),
        )


class PersistentServerTimingBackend:
    """One real psql backend, sequential independent measured transactions.

    A successful COMMIT keeps the backend and its metadata cache alive.
    SET LOCAL settings/roles revert at COMMIT.  Any transaction or parsing
    failure invalidates the entire backend; it cannot be reused afterwards.
    """
    def __init__(self, pg_env: PostgresEnv, timeout_s: float = 7200):
        self.pg_env = pg_env
        self.closed = False
        self._active = False
        self._channel = _PsqlInteractiveChannel(pg_env, timeout_s=timeout_s)

    def _transaction(self, pg_env: PostgresEnv, *, read_only: bool) -> PostgresTransactionSession:
        if self.closed:
            raise PostgresError("persistent server timing backend is closed")
        if self._active:
            raise PostgresError("persistent server timing backend already has an active transaction")
        if pg_env != self.pg_env:
            raise ValueError("persistent server timing backend database environment mismatch")
        self._active = True
        try:
            return _PersistentTransactionSession(self, read_only=read_only)
        except Exception:
            self.invalidate()
            self._active = False
            raise

    def invalidate(self) -> None:
        self.close()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._channel.close()

    def __enter__(self) -> "PersistentServerTimingBackend":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _sha256(sql: str) -> str:
    return "sha256:" + hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _nonnegative_time(document: Mapping[str, Any], name: str) -> float:
    value = document.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PostgresError(f"EXPLAIN ANALYZE lacks a numeric {name}")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise PostgresError(f"EXPLAIN ANALYZE has an invalid {name}")
    return result


def parse_server_explain(raw: str) -> dict[str, Any]:
    """Strictly parse one PostgreSQL JSON plan; missing times are not zero."""
    try:
        document = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PostgresError("EXPLAIN ANALYZE returned malformed JSON") from exc
    if (
        not isinstance(document, list)
        or len(document) != 1
        or not isinstance(document[0], Mapping)
        or not isinstance(document[0].get("Plan"), Mapping)
    ):
        raise PostgresError("EXPLAIN ANALYZE must return one document with a Plan")
    planning = _nonnegative_time(document[0], "Planning Time")
    execution = _nonnegative_time(document[0], "Execution Time")
    return {
        "server_planning_ms": planning,
        "server_execution_ms": execution,
        "explain_json": document,
    }


def _query_statement(sql: str) -> str:
    statement = _validate_single_transaction_statement(sql)
    # Existing benchmark renderers produce SELECT/WITH statements.  Reject
    # already-explained queries and session/state commands before opening PG.
    # The established validator already checks comments, quotes and single-
    # statement boundaries.  Skip its validated leading comments only when
    # locating the head; retain them in both executed SQL and identity hashes.
    cursor = 0
    while cursor < len(statement):
        if statement[cursor].isspace():
            cursor += 1
        elif statement.startswith("--", cursor):
            end = statement.find("\n", cursor + 2)
            cursor = len(statement) if end < 0 else end + 1
        elif statement.startswith("/*", cursor):
            depth = 1
            cursor += 2
            while depth and cursor < len(statement):
                if statement.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif statement.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
        else:
            break
    head = re.match(r"[A-Za-z_][A-Za-z0-9_]*", statement[cursor:])
    if head is None or head.group(0).upper() not in {"SELECT", "WITH", "VALUES"}:
        raise PostgresError("server timing requires one complete SELECT/WITH/VALUES query")
    return statement


def _validation_statements(validation_sql: str | None) -> list[str]:
    if validation_sql is None or validation_sql == "":
        return []
    if not isinstance(validation_sql, str):
        raise TypeError("validation_sql must be SQL text or None")
    # The existing artifact helper emits semicolon/newline-separated SELECTs
    # with compact, quoted JSON literals.  Each piece is still independently
    # checked by the established single-statement validator.
    return [
        _query_statement(piece)
        for piece in validation_sql.split(";\n")
        if piece.strip()
    ]


def _runtime_facts(raw: str, requested_role: str | None, read_only: bool) -> dict[str, Any]:
    try:
        facts = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PostgresError("server timing returned malformed runtime facts") from exc
    required = {
        "current_user", "session_user", "row_security", "isolation_level",
        "transaction_read_only", "work_mem", "shared_buffers",
    }
    if (
        not isinstance(facts, dict)
        or set(facts) != required
        or any(not isinstance(facts[key], str) or not facts[key] for key in required)
    ):
        raise PostgresError("server timing returned incomplete runtime facts")
    if facts["row_security"] != "on" or facts["isolation_level"] != "repeatable read":
        raise PostgresError("server timing runtime is not RLS-on REPEATABLE READ")
    if requested_role is not None and facts["current_user"] != requested_role:
        raise PostgresError("server timing role does not match the requested role")
    if facts["transaction_read_only"] != ("on" if read_only else "off"):
        raise PostgresError("server timing read-only mode does not match the declaration")
    return facts


def run_server_timed_sql(
    sql: str,
    pg_env: PostgresEnv,
    *,
    role: str | None = None,
    validation_sql: str | None = None,
    timeout_s: float = 7200,
    read_only: bool = False,
    backend: PersistentServerTimingBackend | None = None,
) -> dict[str, Any]:
    """Execute one analyzed complete query in one REPEATABLE READ transaction.

    ``query_server_ms`` is PostgreSQL's body Planning Time + Execution Time,
    plus the same two times for every required artifact validation statement.
    Validation precedes any role switch, matching the existing artifact gate.
    The query itself is never rerun to fetch results in this function.
    """
    statement = _query_statement(sql)
    validations = _validation_statements(validation_sql)
    if role is not None and (not isinstance(role, str) or _ROLE_NAME.fullmatch(role) is None):
        raise ValueError("invalid benchmark role")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        raise ValueError("timeout_s must be finite and positive")
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("timeout_s must be finite and positive")
    if not isinstance(read_only, bool):
        raise ValueError("read_only must be boolean")

    session = (
        PostgresTransactionSession(
            pg_env, read_only=read_only, statement_timeout_s=timeout_s,
        )
        if backend is None
        else backend._transaction(pg_env, read_only=read_only)
    )
    failed = False
    try:
        for setting in (
            "SET LOCAL search_path TO pg_catalog, public",
            "SET LOCAL jit = off",
            "SET LOCAL max_parallel_workers_per_gather = 0",
            "SET LOCAL plan_cache_mode = force_custom_plan",
            "SET LOCAL row_security = on",
            "SET LOCAL statement_timeout = " + str(max(1, math.ceil(timeout_s * 1000))),
        ):
            session.execute(setting)

        validation_observations = []
        for validation in validations:
            raw = session.execute(EXPLAIN_PREFIX + validation)
            parsed = parse_server_explain(raw)
            validation_observations.append({
                "sql": validation,
                "sql_hash": _sha256(validation),
                **parsed,
                "explain_raw": raw,
            })
        validation_ms = sum(
            item["server_planning_ms"] + item["server_execution_ms"]
            for item in validation_observations
        )
        if role is not None:
            session.execute('SET LOCAL ROLE "' + role + '"')
        runtime = _runtime_facts(session.execute(_RUNTIME_SQL), role, read_only)
        raw = session.execute(EXPLAIN_PREFIX + statement)
        parsed = parse_server_explain(raw)
        identity = session.identity.to_dict()
        total_server_ms = (
            parsed["server_planning_ms"] + parsed["server_execution_ms"]
            + validation_ms
        )
        if not math.isfinite(total_server_ms):
            raise PostgresError("EXPLAIN ANALYZE total server time is not finite")
        session.commit()

        return {
            "query_server_ms": total_server_ms,
            "server_planning_ms": parsed["server_planning_ms"],
            "server_execution_ms": parsed["server_execution_ms"],
            "validation_server_ms": validation_ms,
            "sql": sql,
            "sql_hash": _sha256(sql),
            "executed_sql_hash": _sha256(sql),
            "normalized_sql_hash": _sha256(statement),
            "role": runtime["current_user"],
            "requested_role": role,
            "row_security": runtime["row_security"],
            "read_only": read_only,
            "runtime_facts": runtime,
            "transaction_identity": identity,
            "query_explain_json": parsed["explain_json"],
            "query_explain_raw": raw,
            "validation_explain_json": [item["explain_json"] for item in validation_observations],
            "validation_observations": validation_observations,
            "query_executions": 1,
            "explain_analyze_query_executions": 1,
            "ordinary_query_executions": 0,
            "diagnostic_query_executions": 0,
            "validation_query_executions": len(validations),
            "server_time_scope": SERVER_TIME_SCOPE,
            "correctness_scope": "separate_untimed_full_result_comparison",
            "persistent_backend": backend is not None,
            "measurement_batch_count": 1,
        }
    except Exception:
        failed = True
        if backend is not None:
            backend.invalidate()
        raise
    finally:
        try:
            # A failed persistent channel is already closed and cannot receive
            # a cleanup ROLLBACK.  Preserve the original failure instead.
            if not (failed and backend is not None):
                session.close()
        finally:
            if backend is not None:
                backend._active = False


def run_server_timing_block(
    sql: str,
    pg_env: PostgresEnv,
    *,
    backend: PersistentServerTimingBackend | None = None,
    batch_count: int = 1,
    role: str | None = None,
    validation_sql: str | None = None,
    timeout_s: float = 7200,
    read_only: bool = False,
) -> dict[str, Any]:
    """Mean of all fixed-K complete SQL executions; no trimming or selection.

    Each member has its own RR transaction and applicable validation.  K is
    declared by case class before sampling, not chosen from observed results.
    The block is one statistical repetition, not K independent repetitions.
    """
    if isinstance(batch_count, bool) or not isinstance(batch_count, int) or batch_count < 1:
        raise ValueError("batch_count must be a positive integer")
    owned = backend is None
    if owned:
        backend = PersistentServerTimingBackend(pg_env, timeout_s=timeout_s)
    try:
        observations = [
            run_server_timed_sql(
                sql, pg_env, backend=backend, role=role,
                validation_sql=validation_sql, timeout_s=timeout_s,
                read_only=read_only,
            )
            for _ in range(batch_count)
        ]
        result = dict(observations[0])
        for name in ("server_planning_ms", "server_execution_ms", "validation_server_ms"):
            result[name] = math.fsum(item[name] for item in observations) / batch_count
        result["query_server_ms"] = (
            result["server_planning_ms"] + result["server_execution_ms"]
            + result["validation_server_ms"]
        )
        result.update({
            "measurement_batch_count": batch_count,
            "raw_server_measurements": observations,
            "query_executions": batch_count,
            "explain_analyze_query_executions": batch_count,
            "ordinary_query_executions": 0,
            "diagnostic_query_executions": 0,
            "validation_query_executions": sum(
                item["validation_query_executions"] for item in observations
            ),
            "server_sample_aggregation": "arithmetic_mean_of_all_fixed_batch_members",
            "transaction_identity_scope": "first_member_see_each_raw_transaction_identity",
            "explain_json_scope": "first_member_see_raw_server_measurements_for_all_plans",
        })
        return result
    finally:
        if owned and backend is not None:
            backend.close()
