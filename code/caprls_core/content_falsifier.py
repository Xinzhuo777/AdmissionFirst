"""Recomposition checks for content-boundary cases."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

BOUND_RUNNER_WRAPPER_OPEN = "WITH caprls_access_root AS MATERIALIZED (\n"
BOUND_RUNNER_WRAPPER_CLOSE = "\n)"


class ContentFalsifierError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Digest encodings — one per frozen authority, transcribed and re-derived here
# ---------------------------------------------------------------------------
def sha256_plain(text: str) -> str:
    """``sha256(text.encode('utf-8'))`` — E2 and the E3 ordinary layer."""

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_canonical_json(payload: Mapping[str, Any], ensure_ascii: bool = True) -> str:
    """``sha256(json.dumps(payload, sort_keys=True, separators=(',',':')))``.

    ``planner/root_selection.py:_digest`` (``ensure_ascii=True``) and
    ``caprls_core/e10_study.py:_digest`` (the ``json`` default, also True).
    """

    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii
    )
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def digest_for(encoding: str, text: str) -> str:
    if encoding == "plain_sha256_utf8":
        return sha256_plain(text)
    if encoding == "canonical_json_exact_runner_sql":
        return sha256_canonical_json({"exact_runner_sql": text})
    if encoding == "canonical_json_runner_sql":
        return sha256_canonical_json({"runner_sql": text})
    raise ContentFalsifierError("unknown digest encoding: {}".format(encoding))


# ---------------------------------------------------------------------------
# Frozen-record accessors
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> Mapping[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def split_access_root(bound_runner_sql: str) -> Tuple[str, str]:
    """Split ``WITH caprls_access_root AS MATERIALIZED ( <body> )<continuation>``."""

    if not bound_runner_sql.startswith(BOUND_RUNNER_WRAPPER_OPEN):
        raise ContentFalsifierError("frozen bound runner does not open the access root")
    start = bound_runner_sql.index("(")
    depth = 0
    for index in range(start, len(bound_runner_sql)):
        char = bound_runner_sql[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                body = bound_runner_sql[start + 1:index]
                continuation = bound_runner_sql[index + 1:]
                if body.startswith("\n"):
                    body = body[1:]
                if body.endswith("\n"):
                    body = body[:-1]
                return body, continuation
    raise ContentFalsifierError("frozen bound runner has an unbalanced access root")


def recompose_bound_runner(body: str, continuation: str) -> str:
    """The canonical composition of ``root_selection._compose_exact_bound_runner_sql``."""

    return BOUND_RUNNER_WRAPPER_OPEN + body + BOUND_RUNNER_WRAPPER_CLOSE + continuation


def lift_named_cte(runner_sql: str, cte: str) -> str:
    """Lift ``WITH <cte> AS MATERIALIZED ( <body> )`` verbatim (§6.2).

    A text-only extraction is never accepted on its own: the caller must also
    prove (i) substring containment in the recomposed statement and (ii) digest
    equality of the recomposed statement against the frozen hash.
    """

    marker = "WITH {} AS MATERIALIZED (".format(cte)
    if marker not in runner_sql:
        raise ContentFalsifierError("named CTE {} not found in the frozen runner".format(cte))
    start = runner_sql.index(marker) + len(marker) - 1
    depth = 0
    for index in range(start, len(runner_sql)):
        char = runner_sql[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return runner_sql[start + 1:index]
    raise ContentFalsifierError("named CTE {} is unbalanced".format(cte))


# ---------------------------------------------------------------------------
# Per-cell offline falsification
# ---------------------------------------------------------------------------
@dataclass
class FalsifierResult:
    cell_id: str
    short_id: str
    family: str
    level: str
    runner_identity: str
    detail: str = ""
    checks: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "short_id": self.short_id,
            "family": self.family,
            "level": self.level,
            "runner_identity": self.runner_identity,
            "detail": self.detail,
            "checks": self.checks or {},
        }


def falsify_e3_offline(root: Path, cell: Mapping[str, Any]) -> FalsifierResult:
    """Recompose the frozen E3 bound runner and re-digest.  No database."""

    frozen = cell["frozen"]
    record = _load_json(Path(root) / frozen["record"])
    text = record["sql"]["text"]
    body, continuation = split_access_root(text)
    recomposed = recompose_bound_runner(body, continuation)
    checks: Dict[str, Any] = {}

    checks["recomposition_is_byte_identical_to_frozen_text"] = recomposed == text
    checks["selected_runner_digest_matches"] = (
        digest_for(frozen["runner_sql_digest_encoding"], recomposed)
        == frozen["runner_sql_digest"]
    )
    checks["bound_runner_plain_digest_matches"] = (
        sha256_plain(text) == frozen["bound_runner_sql_digest_plain"]
    )
    checks["spec_access_root_body_digest_matches"] = (
        sha256_plain(body) == cell["candidate"]["frozen_access_root_body_digest"]
    )
    checks["spec_continuation_digest_matches"] = (
        sha256_plain(continuation) == cell["candidate"]["frozen_continuation_digest"]
    )
    checks["selected_template_matches"] = (
        record["template_id"] == frozen["selected_template_id"]
    )
    checks["git_commit_matches"] = record["git_commit"] == frozen["git_commit"]
    checks["manifest_sha256_matches"] = (
        record["manifest_sha256"] == frozen["manifest_sha256"]
    )

    # Declared B_c and r_c must appear verbatim inside the frozen access root.
    boundary = cell["boundary"]
    checks["declared_projection_present"] = (
        "SELECT " + boundary["candidate_projection_sql"] + " FROM (" in body
    )
    checks["declared_r_c_present"] = (
        "AS sel WHERE " + boundary["refinement"]["r_c"] + ") AS proj" in body
    )

    # The ordinary (perf) layer's own record integrity.
    ordinary = _load_json(Path(root) / frozen["ordinary_record"])
    checks["ordinary_runner_sql_digest_matches"] = (
        digest_for(
            frozen["ordinary_runner_sql_digest_encoding"], ordinary["sql"]["runner_sql"]
        )
        == frozen["ordinary_runner_sql_digest"]
    )
    checks["ordinary_runner_sql_source_matches"] = (
        ordinary["sql"]["runner_sql_source"] == frozen["ordinary_runner_sql_source"]
    )

    failed = sorted(name for name, ok in checks.items() if not ok)
    return FalsifierResult(
        cell_id=cell["cell_id"],
        short_id=cell["short_id"],
        family="E3",
        level="frozen_transcription",
        runner_identity="byte_identical" if not failed else "differs",
        detail="" if not failed else "failed: " + ", ".join(failed),
        checks=checks,
    )


def falsify_frozen_record_integrity(root: Path, cell: Mapping[str, Any]) -> FalsifierResult:
    """Content-boundary verification helper."""

    frozen = cell["frozen"]
    record = _load_json(Path(root) / frozen["record"])
    runner_sql = record["sql"]["runner_sql"]
    checks: Dict[str, Any] = {
        "frozen_runner_sql_digest_matches": (
            digest_for(frozen["runner_sql_digest_encoding"], runner_sql)
            == frozen["runner_sql_digest"]
        ),
        "git_commit_matches": (
            record["implementation"]["git_commit"] == frozen["git_commit"]
        ),
        "manifest_sha256_matches": record["manifest_hash"] == frozen["manifest_sha256"],
        "frozen_result_row_count_matches": (
            record["result"]["row_count"] == frozen["frozen_result_row_count"]
        ),
    }
    candidate = cell["candidate"]
    if candidate.get("cte_name"):
        body = lift_named_cte(runner_sql, candidate["cte_name"])
        checks["cte_body_digest_matches"] = (
            sha256_plain(body) == candidate["frozen_cte_body_digest"]
        )
        checks["declared_projection_present"] = (
            cell["boundary"]["candidate_projection_sql"] in body
        )
        checks["cte_body_is_contained_in_runner"] = body in runner_sql
    else:
        checks["statement_digest_matches"] = (
            sha256_plain(
                runner_sql
                if cell["family"] == "E10"
                else runner_sql[runner_sql.index("SELECT count(*)"):].strip().rstrip(";")
            )
            == candidate["frozen_statement_digest"]
        )
        checks["frozen_select_list_is_count_star"] = "count(*)" in runner_sql
    r_c = cell["boundary"]["refinement"].get("r_c")
    if r_c and cell["family"] == "E10":
        checks["declared_r_c_present"] = r_c in runner_sql

    failed = sorted(name for name, ok in checks.items() if not ok)
    return FalsifierResult(
        cell_id=cell["cell_id"],
        short_id=cell["short_id"],
        family=cell["family"],
        level="frozen_transcription",
        runner_identity="deferred_requires_database" if not failed else "differs",
        detail=(
            "frozen record transcription verified; HEAD recomposition requires a "
            "rebuilt database (memo 6.3)"
            if not failed
            else "failed: " + ", ".join(failed)
        ),
        checks=checks,
    )


def falsify_head_replan(
    cell: Mapping[str, Any], head_runner_sql: str
) -> FalsifierResult:
    """Content-boundary verification helper."""

    frozen = cell["frozen"]
    observed = digest_for(frozen["runner_sql_digest_encoding"], head_runner_sql)
    identical = observed == frozen["runner_sql_digest"]
    return FalsifierResult(
        cell_id=cell["cell_id"],
        short_id=cell["short_id"],
        family=cell["family"],
        level="head_replan",
        runner_identity="byte_identical" if identical else "differs",
        detail="" if identical else "observed {} != frozen {}".format(
            observed, frozen["runner_sql_digest"]),
        checks={
            "observed_digest": observed,
            "frozen_digest": frozen["runner_sql_digest"],
            "encoding": frozen["runner_sql_digest_encoding"],
        },
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def load_spec(spec_path: Path) -> Mapping[str, Any]:
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != "caprls-content-cells-v1":
        raise ContentFalsifierError("content cell spec has the wrong schema")
    return data


def run_offline(root: Path, spec_path: Optional[Path] = None) -> Dict[str, Any]:
    """Run every falsification that needs no database (§6.3)."""

    root = Path(root)
    spec_path = Path(spec_path) if spec_path else root / "specs" / "content_cells.yaml"
    spec = load_spec(spec_path)
    results: List[FalsifierResult] = []
    for cell in spec["cells"]:
        if cell["family"] == "E3":
            results.append(falsify_e3_offline(root, cell))
        else:
            results.append(falsify_frozen_record_integrity(root, cell))

    per_family: Dict[str, Dict[str, int]] = {}
    for result in results:
        bucket = per_family.setdefault(result.family, {})
        bucket[result.runner_identity] = bucket.get(result.runner_identity, 0) + 1

    e3 = [r for r in results if r.family == "E3"]
    return {
        "schema": "caprls-content-falsifier-v1",
        "level": "offline",
        "spec_digest": sha256_plain(Path(spec_path).read_text(encoding="utf-8")),
        "cells": [r.to_dict() for r in results],
        "per_family": per_family,
        "e3_offline_recomposition": {
            "cells": len(e3),
            "byte_identical": sum(1 for r in e3 if r.runner_identity == "byte_identical"),
            "differs": sum(1 for r in e3 if r.runner_identity == "differs"),
        },
        "deferred_to_database": sorted(
            r.short_id for r in results
            if r.runner_identity == "deferred_requires_database"
        ),
        "status": "pass" if all(r.runner_identity != "differs" for r in results) else "fail",
    }
