"""PG column observations for the finite continuation proof premises.

The SQL and parser bind an actual adapter observation to a current proof.
They issue no Gamma fact or execution authority. A caller must execute the
probe under its trusted session and combine the column guard with its table,
role, authorization and same-snapshot execution checks.
"""
from __future__ import annotations

import json

from planner.continuation_necessity import (
    BoundNecessitySource, NecessityEvidence, NecessityError,
    require_necessity_evidence,
)
from planner.continuation_refinement import (
    ContinuationRefinement, _hash, _json, _schema_requirements,
    _validate_schema_claims, require_continuation_refinement,
)


SCHEMA = "caprls_continuation_schema_observation_v1"
PREFIX = "CAPRLS_CONTINUATION_SCHEMA:"


def _literal(value: str) -> str:
    if type(value) is not str or "\x00" in value:
        raise NecessityError("schema SQL literal must be an exact string")
    return "E'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _columns_expression(report: dict) -> str:
    requirements = _schema_requirements(report)
    rows = ",\n".join(
        "(" + ",".join(_literal(value) for value in
                        (alias, requirements[(alias, column)]["relation_name"], column)) + ")"
        for alias, column in sorted(requirements)
    )
    if not rows:
        raise NecessityError("continuation schema inventory is empty")
    # LEFT joins retain missing objects as NULLs; validation then rejects
    # rather than silently shrinking the column inventory. C ordering matches
    # Python's finite ASCII identifiers and avoids inherited SQL collations.
    return """(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'alias', e.alias, 'relation_name', e.relation_name,
      'relation_oid', c.oid::bigint, 'column_name', e.column_name,
      'attnum', a.attnum::integer, 'type_namespace', tn.nspname::text,
      'type_name', pg_catalog.format_type(a.atttypid, NULL),
      'type_oid', a.atttypid::bigint, 'type_kind', t.typtype::text,
      'typmod', a.atttypmod, 'generated', a.attgenerated::text,
      'nullable', NOT a.attnotnull,
      'collation_oid', a.attcollation::bigint,
      'collation', CASE WHEN a.attcollation=0 THEN NULL
                        ELSE cn.nspname::text || '.' || co.collname::text END,
      'collation_deterministic', CASE WHEN a.attcollation=0 THEN NULL
                                      ELSE co.collisdeterministic END)
      ORDER BY e.alias COLLATE pg_catalog.\"C\", e.column_name COLLATE pg_catalog.\"C\")
    FROM (VALUES """ + rows + """) AS e(alias, relation_name, column_name)
    LEFT JOIN pg_catalog.pg_namespace n ON n.nspname='public'
    LEFT JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid
      AND c.relname=e.relation_name COLLATE pg_catalog.\"C\"
    LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
      AND a.attname=e.column_name COLLATE pg_catalog.\"C\"
      AND a.attnum>0 AND NOT a.attisdropped
    LEFT JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
    LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
    LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
    LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace)"""


def continuation_schema_probe_sql(source: BoundNecessitySource,
                                  evidence: NecessityEvidence) -> str:
    report = require_necessity_evidence(evidence, source)
    return ("SELECT " + _literal(PREFIX) + " || pg_catalog.jsonb_build_object("
            "'schema', " + _literal(SCHEMA) + ", 'proof_digest', " + _literal(_hash(report))
            + ", 'columns', " + _columns_expression(report) + ")::text;\n")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NecessityError("schema observation has duplicate JSON keys")
        result[key] = value
    return result


def parse_continuation_schema_observation(
    source: BoundNecessitySource, evidence: NecessityEvidence, stdout: str,
) -> list[dict]:
    """Normalize one actual probe output; caller owns its observation origin."""
    report = require_necessity_evidence(evidence, source)
    if type(stdout) is not str:
        raise NecessityError("schema observation output must be an exact string")
    frames = [line[len(PREFIX):] for line in stdout.splitlines() if line.startswith(PREFIX)]
    if len(frames) != 1:
        raise NecessityError("schema observation needs exactly one frame")
    try:
        payload = json.loads(frames[0], object_pairs_hook=_unique_object)
    except (TypeError, ValueError) as exc:
        raise NecessityError("malformed schema observation JSON") from exc
    if (type(payload) is not dict or set(payload) != {"schema", "proof_digest", "columns"}
        or payload["schema"] != SCHEMA or payload["proof_digest"] != _hash(report)):
        raise NecessityError("schema observation differs from its current proof")
    return _validate_schema_claims(report, payload["columns"])


def continuation_schema_guard_sql(descriptor: ContinuationRefinement) -> str:
    """Column-premise guard, to accompany the adapter's existing guards."""
    payload = require_continuation_refinement(descriptor)
    return ("(" + _columns_expression(payload["necessity"])
            + " IS NOT DISTINCT FROM " + _literal(_json(payload["schema_claims"])) + "::jsonb)")
