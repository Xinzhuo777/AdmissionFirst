"""Conservative PC scope grammar and exact access-root wrapper decoding.

This is not an SQL sanitizer. Purity additionally needs a validator-issued
builtin-catalog fact and the original registered strict result. Unsupported
expressions retain the nested composition. No authorization CTE is inlined.
"""
from __future__ import annotations

import re

from .continuation_necessity import NecessityError, _sql_tokens


_ID = r"[a-z_][a-z_0-9]*"
_HEADER = re.compile(r"\s*(" + _ID + r")\s+AS\s+(NOT\s+)?MATERIALIZED\s*\(", re.I)
_PC = re.compile(
    r"auth AS MATERIALIZED \(SELECT (?P<columns>.*?) FROM public\.(?P<relation>"
    + _ID + r") (?P<alias>" + _ID + r") WHERE (?P<predicate>.*)\)\Z", re.S)


def safe_pc_predicate(sql: str, alias: str) -> bool:
    """Finite qualified-column comparisons/AND/OR/BETWEEN, no calls or casts.

    The adapter must establish builtin types, compatible literals and pure
    comparison semantics. This syntax check issues no catalog premise.
    """
    try:
        tokens = _sql_tokens(sql)
        pos = 0

        def take(value):
            nonlocal pos
            if pos < len(tokens) and tokens[pos] == value:
                pos += 1
                return True
            return False

        def literal():
            nonlocal pos
            if pos >= len(tokens):
                raise ValueError()
            item = tokens[pos]
            if not (re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", item)
                    or (item.startswith("'") and "\\" not in item)):
                raise ValueError()
            pos += 1

        def atom():
            nonlocal pos
            if take("("):
                expression()
                if not take(")"):
                    raise ValueError()
                return
            if not take(alias) or not take(".") or pos >= len(tokens):
                raise ValueError()
            if re.fullmatch(_ID, tokens[pos]) is None:
                raise ValueError()
            pos += 1
            if take("between"):
                literal()
                if not take("and"):
                    raise ValueError()
                literal()
            else:
                if pos >= len(tokens) or tokens[pos] not in {"=", "<>", "<", ">", "<=", ">="}:
                    raise ValueError()
                pos += 1
                literal()

        def expression():
            atom()
            while take("and") or take("or"):
                atom()

        expression()
        return pos == len(tokens)
    except (NecessityError, ValueError, RecursionError):
        return False


def closed_pc_cte_name(cte: str) -> str | None:
    """Recognize the emitter's single closed, explicitly projected PC CTE."""
    match = _PC.fullmatch(cte)
    if match is None:
        return None
    alias = match.group("alias")
    columns = match.group("columns").split(", ")
    if not columns or any(re.fullmatch(re.escape(alias) + r"\." + _ID, col) is None
                          for col in columns):
        return None
    if not safe_pc_predicate(match.group("predicate"), alias):
        return None
    return "auth"


def continuation_avoids_name(sql: str, name: str) -> bool:
    try:
        # Quoted identifiers/comments/unknown syntax fall back conservatively.
        return name not in _sql_tokens(sql)
    except (NecessityError, RecursionError):
        return False


def _one_auth_reference(sql: str) -> bool:
    try:
        tokens = _sql_tokens(sql)
        return sum(pair == ("from", "auth") for pair in zip(tokens, tokens[1:])) == 1
    except (NecessityError, RecursionError):
        return False


def _closing_paren(sql: str, start: int) -> int | None:
    """Match one CTE body, respecting SQL strings, identifiers and comments."""
    depth, pos = 1, start
    while pos < len(sql):
        char = sql[pos]
        if char in {"'", '"'}:
            quote = char
            pos += 1
            while pos < len(sql):
                if sql[pos] == quote:
                    pos += 1
                    if pos < len(sql) and sql[pos] == quote:
                        pos += 1
                        continue
                    break
                # Refuse escape-string ambiguity instead of guessing a GUC.
                if sql[pos] == "\\":
                    return None
                pos += 1
            else:
                return None
            continue
        if sql.startswith("--", pos):
            newline = sql.find("\n", pos + 2)
            if newline < 0:
                return None
            pos = newline + 1
            continue
        if sql.startswith("/*", pos):
            comment_depth = 1
            pos += 2
            while pos < len(sql) and comment_depth:
                if sql.startswith("/*", pos):
                    comment_depth += 1
                    pos += 2
                elif sql.startswith("*/", pos):
                    comment_depth -= 1
                    pos += 2
                else:
                    pos += 1
            if comment_depth:
                return None
            continue
        if char == "$":
            tag = re.match(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$", sql[pos:])
            if tag is not None:
                close = sql.find(tag.group(), pos + len(tag.group()))
                if close < 0:
                    return None
                pos = close + len(tag.group())
                continue
            parameter = re.match(r"\$(?:[A-Za-z_][A-Za-z_0-9]*|[0-9]+)", sql[pos:])
            if parameter is None:
                return None
            pos += len(parameter.group())
            continue
        if char == ";":
            return None
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if not depth:
                return pos
        pos += 1
    return None


def decode_access_root_materialized(sql: str) -> bool | None:
    """Decode legacy root-first or canonical one-PC-prelude WITH, fail closed.

    Header matching is anchored at every position; a root-like name hidden in
    a string, comment or nested query never becomes the top-level root.
    Runtime ownership still requires byte-exact canonical recomposition.
    """
    if type(sql) is not str:
        return None
    opening = re.match(r"\A\s*WITH\b", sql, re.I)
    if opening is None:
        return None
    pos, entries = opening.end(), []
    while len(entries) < 3:
        header = _HEADER.match(sql, pos)
        if header is None:
            return None
        end = _closing_paren(sql, header.end())
        if end is None:
            return None
        entries.append((header.group(1).lower(), header.group(2) is None,
                        sql[pos:end + 1].strip(), sql[header.end():end]))
        pos = end + 1
        while pos < len(sql) and sql[pos].isspace():
            pos += 1
        if pos < len(sql) and sql[pos] == ",":
            pos += 1
            continue
        break
    if re.match(r"SELECT\b", sql[pos:], re.I) is None:
        return None
    if len(entries) == 1 and entries[0][0] == "caprls_access_root":
        return entries[0][1]
    if (len(entries) == 2 and entries[0][0] == "auth"
            and entries[1][0] == "caprls_access_root"
            and closed_pc_cte_name(entries[0][2]) == "auth"
            and re.match(r"\s*SELECT\b", entries[1][3], re.I)
            and _one_auth_reference(entries[1][3])
            and continuation_avoids_name(sql[pos:], "auth")):
        return entries[1][1]
    return None
