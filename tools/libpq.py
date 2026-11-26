"""Minimal synchronous libpq client for the native AF experiments.

PQexec uses the simple query protocol. All calls decode and retain every row,
including NULLs and duplicate rows, before returning.
"""

from ctypes import CDLL, CFUNCTYPE, POINTER, c_char_p, c_int, c_uint, c_void_p
from ctypes import string_at
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class QueryError(RuntimeError):
    def __init__(self, message: str, sqlstate: Optional[str] = None):
        super().__init__(message)
        self.sqlstate = sqlstate


@dataclass(frozen=True)
class Result:
    columns: tuple[tuple[str, int], ...]
    rows: tuple[tuple[Optional[str], ...], ...]
    command: str


_NoticeReceiver = CFUNCTYPE(None, c_void_p, c_void_p)


class LibPQ:
    def __init__(self, library: Path):
        self.path = library.resolve(strict=True)
        self.lib = CDLL(str(self.path))
        signatures = {
            "PQconnectdbParams": (c_void_p, POINTER(c_char_p), POINTER(c_char_p), c_int),
            "PQstatus": (c_int, c_void_p),
            "PQerrorMessage": (c_char_p, c_void_p),
            "PQfinish": (None, c_void_p),
            "PQsetNoticeReceiver": (_NoticeReceiver, c_void_p, _NoticeReceiver, c_void_p),
            "PQexec": (c_void_p, c_void_p, c_char_p),
            "PQresultStatus": (c_int, c_void_p),
            "PQresultErrorMessage": (c_char_p, c_void_p),
            "PQresultErrorField": (c_char_p, c_void_p, c_int),
            "PQcmdStatus": (c_char_p, c_void_p),
            "PQntuples": (c_int, c_void_p),
            "PQnfields": (c_int, c_void_p),
            "PQfname": (c_char_p, c_void_p, c_int),
            "PQftype": (c_uint, c_void_p, c_int),
            "PQgetisnull": (c_int, c_void_p, c_int, c_int),
            "PQgetlength": (c_int, c_void_p, c_int, c_int),
            "PQgetvalue": (c_void_p, c_void_p, c_int, c_int),
            "PQclear": (None, c_void_p),
        }
        for name, (result, *arguments) in signatures.items():
            function = getattr(self.lib, name)
            function.restype = result
            function.argtypes = arguments

    def connect(self, *, socket_dir: Path, port: int, database: str, role: str):
        if not socket_dir.is_absolute() or not socket_dir.is_dir():
            raise ValueError("an absolute existing Unix socket directory is required")
        if not 1 <= port <= 65535 or not database or not role:
            raise ValueError("invalid port, database or role")
        parameters = {
            "host": str(socket_dir),
            "port": str(port),
            "dbname": database,
            "user": role,
            "connect_timeout": "10",
            "client_encoding": "UTF8",
            "options": "",
        }
        array = c_char_p * (len(parameters) + 1)
        keys = array(*(key.encode("ascii") for key in parameters))
        values = array(*(value.encode("utf-8") for value in parameters.values()))
        return Connection(self.lib, self.lib.PQconnectdbParams(keys, values, 0))


class Connection:
    def __init__(self, lib, connection):
        self.lib = lib
        self.connection = connection
        self.notices: list[str] = []
        if not connection:
            raise QueryError("PQconnectdbParams could not allocate a connection")
        if lib.PQstatus(connection) != 0:  # CONNECTION_OK
            message = lib.PQerrorMessage(connection).decode("utf-8", errors="replace")
            self.close()
            raise QueryError(message.strip())
        self._receiver = _NoticeReceiver(self._record_notice)
        lib.PQsetNoticeReceiver(connection, self._receiver, None)

    def _record_notice(self, _context, result):
        message = self.lib.PQresultErrorMessage(result)
        if message:
            self.notices.append(message.decode("utf-8", errors="replace").strip())

    def execute(self, sql: str) -> Result:
        if self.connection is None:
            raise QueryError("connection is closed")
        if "\x00" in sql:
            raise ValueError("query contains NUL")
        lib = self.lib
        result = lib.PQexec(self.connection, sql.encode("utf-8"))
        if not result:
            message = lib.PQerrorMessage(self.connection).decode("utf-8", errors="replace")
            raise QueryError(message.strip())
        try:
            if lib.PQresultStatus(result) not in (1, 2):  # COMMAND_OK, TUPLES_OK
                message = lib.PQresultErrorMessage(result).decode("utf-8", errors="replace")
                sqlstate = lib.PQresultErrorField(result, ord("C"))  # PG_DIAG_SQLSTATE
                raise QueryError(message.strip(), sqlstate.decode("ascii") if sqlstate else None)
            fields = range(lib.PQnfields(result))
            columns = tuple((lib.PQfname(result, field).decode("utf-8"), lib.PQftype(result, field))
                            for field in fields)
            rows = tuple(tuple(self._value(result, row, field) for field in fields)
                         for row in range(lib.PQntuples(result)))
            command = lib.PQcmdStatus(result).decode("utf-8")
            return Result(columns, rows, command)
        finally:
            lib.PQclear(result)

    def _value(self, result, row: int, field: int) -> Optional[str]:
        lib = self.lib
        if lib.PQgetisnull(result, row, field):
            return None
        return string_at(lib.PQgetvalue(result, row, field),
                         lib.PQgetlength(result, row, field)).decode("utf-8")

    def close(self) -> None:
        if self.connection is not None:
            self.lib.PQfinish(self.connection)
            self.connection = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
