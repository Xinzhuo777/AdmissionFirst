"""Validation and generation for IR-SQL equivalence witness packages."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .postgres_runner import PostgresEnv, PostgresError, run_psql_command


SCHEMA_VERSION = "caprls-ir-sql-equivalence-witness-v1"
SPEC_SCHEMA_VERSION = "caprls-ir-sql-equivalence-spec-v1"
DEFAULT_PACKAGES = (
    "E1",
    "E2_PROTOCOL",
    "E3_SF1_RAWPG_V1",
    "E6",
    "E6B_PROTOCOL",
    "E8",
    "SIGMOD_CURRENT_E10",
)
DEFAULT_REQUIRED_EXPERIMENTS = ("E1", "E2", "E3", "E6", "E8", "E10")
NATIVE_RLS_TEMPLATE_IDS = ("native_pg_rls_v1", "native_pg_rls_physical_design_v1")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UNBOUND_SQL_PLACEHOLDER_RE = re.compile(r"<[A-Za-z_][A-Za-z0-9_]*>")
_MATERIALIZED_CTE_SELECT_RE = re.compile(
    r"\bWITH\s+(?P<cte>[A-Za-z_][A-Za-z0-9_]*)\s+AS\s+(?:NOT\s+)?MATERIALIZED\s*"
    r"\(\s*SELECT\s+(?P<projection>.*?)\s+FROM\s",
    flags=re.IGNORECASE | re.DOTALL,
)
ALLOWED_RUNNER_SQL_SOURCES = {
    "sql.ir_equivalence_runner_sql",
    "sql.runner_sql",
    "sql.execution_sql",
    "query.sql",
    "runner_sql",
}


@dataclass(frozen=True)
class IRSQLWitnessIssue:
    path: str
    message: str


@dataclass(frozen=True)
class IRSQLWitnessReport:
    issues: tuple[IRSQLWitnessIssue, ...]
    details: Mapping[str, Any]

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "details": dict(self.details),
            "issues": [issue.__dict__ for issue in self.issues],
        }


@dataclass(frozen=True)
class SQLResultDigest:
    row_count: int
    result_hash: str
    observation_count: int | None = None
    observation_hash: str | None = None


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strip_psql_meta_commands(sql: str) -> str:
    return "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("\\")
    )


def _split_sql_statements(sql: str) -> list[str]:
    normalized = _strip_psql_meta_commands(sql)
    statements = [statement.strip() for statement in normalized.strip().split(";") if statement.strip()]
    if not statements:
        raise PostgresError("IR-SQL equivalence SQL batch is empty")
    return statements


def _is_row_producing_statement(statement: str) -> bool:
    upper = statement.lstrip().upper()
    return upper.startswith(("SELECT", "WITH")) and "CAPRLS_ASSERT_ARTIFACT_VALID" not in upper


def row_sql_from_ir_emitted_sql(emitted_sql: str) -> str:
    """Return the final row-producing SELECT/WITH statement from an emitted SQL batch."""

    query_statements = [
        statement for statement in _split_sql_statements(emitted_sql) if _is_row_producing_statement(statement)
    ]
    if not query_statements:
        raise PostgresError(f"IR-emitted SQL lacks a row-producing SELECT/WITH statement:\n{emitted_sql}")
    return query_statements[-1]


def _prelude_sql_from_batch(sql: str, row_sql: str) -> str:
    prelude: list[str] = []
    row_seen = False
    for statement in _split_sql_statements(sql):
        if statement == row_sql and not row_seen:
            row_seen = True
            continue
        upper = statement.lstrip().upper()
        if upper.startswith(("BEGIN", "COMMIT", "ROLLBACK")):
            continue
        if row_seen and _is_row_producing_statement(statement):
            continue
        prelude.append(statement.rstrip(";"))
    if not prelude:
        return ""
    return ";\n".join(prelude) + ";\n"


def _quote_qualified_identifier(name: str) -> str:
    parts = [part.strip() for part in name.split(".")]
    if not parts or any(not part for part in parts):
        raise ValueError(f"invalid SQL identifier: {name!r}")
    for part in parts:
        if not _IDENTIFIER_RE.fullmatch(part):
            raise ValueError(f"invalid SQL identifier: {name!r}")
    return ".".join(f'"{part}"' for part in parts)


def _normalized_qualified_identifier(name: str) -> str:
    parts = [part.strip().strip('"').lower() for part in name.split(".")]
    return ".".join(parts)


def _audit_observation_json_expr(audit_table: str, alias: str) -> str:
    if _normalized_qualified_identifier(audit_table) == "public.udf_audit":
        return (
            "jsonb_build_object("
            f"'run_id', {alias}.run_id, "
            f"'query_id', {alias}.query_id, "
            f"'plan_id', {alias}.plan_id, "
            f"'occurrence_id', {alias}.occurrence_id, "
            f"'rid', {alias}.rid, "
            f"'value_hash', {alias}.value_hash"
            ")"
        )
    return f"to_jsonb({alias})"


def _json_object_from_psql_output(output: str) -> Mapping[str, Any]:
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            loaded = json.loads(stripped)
            if not isinstance(loaded, Mapping):
                raise PostgresError(f"IR-SQL equivalence digest output is not an object:\n{output}")
            return loaded
    raise PostgresError(f"IR-SQL equivalence digest output did not include JSON:\n{output}")


def digest_sql_result(
    *,
    sql: str,
    pg_env: PostgresEnv,
    audit_table: str | None = None,
) -> SQLResultDigest:
    row_sql = row_sql_from_ir_emitted_sql(sql).rstrip(";")
    prelude_sql = _prelude_sql_from_batch(sql, row_sql)
    audit_relation = _quote_qualified_identifier(audit_table) if audit_table else None
    audit_reset_sql = f"TRUNCATE {audit_relation};" if audit_relation else ""
    audit_json_expr = _audit_observation_json_expr(audit_table, "a") if audit_table else ""
    audit_cte = (
        f"""
        audit_digest AS (
          SELECT
            count(*)::bigint AS observation_count,
            COALESCE(
              jsonb_agg({audit_json_expr} ORDER BY {audit_json_expr}::text),
              '[]'::jsonb
            )::text AS observations_json
          FROM {audit_relation} a
        )
        """
        if audit_relation
        else """
        audit_digest AS (
          SELECT NULL::bigint AS observation_count, NULL::text AS observations_json
        )
        """
    )
    script = f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
{audit_reset_sql}
{prelude_sql}
DROP TABLE IF EXISTS pg_temp.caprls_ir_sql_equivalence_result;
CREATE TEMP TABLE caprls_ir_sql_equivalence_result ON COMMIT DROP AS
{row_sql};
WITH row_digest AS (
  SELECT
    count(*)::bigint AS row_count,
    COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text AS rows_json
  FROM pg_temp.caprls_ir_sql_equivalence_result r
),
{audit_cte}
SELECT jsonb_build_object(
  'row_count', row_digest.row_count,
  'rows_json', row_digest.rows_json,
  'observation_count', audit_digest.observation_count,
  'observations_json', audit_digest.observations_json
)::text
FROM row_digest CROSS JOIN audit_digest;
"""
    payload = _json_object_from_psql_output(run_psql_command(script, pg_env))
    rows_json = str(payload.get("rows_json") or "[]")
    observations_json = payload.get("observations_json")
    return SQLResultDigest(
        row_count=int(payload.get("row_count") or 0),
        result_hash=_sha256_text(rows_json),
        observation_count=(
            None if payload.get("observation_count") is None else int(payload.get("observation_count") or 0)
        ),
        observation_hash=None if observations_json is None else _sha256_text(str(observations_json)),
    )


def evaluate_ir_sql_equivalence_pair(
    *,
    experiment: str,
    case: str,
    template_id: str,
    runner_sql: str,
    ir_sql: str,
    pg_env: PostgresEnv,
    audit_table: str | None = None,
) -> dict[str, Any]:
    runner_digest = digest_sql_result(sql=runner_sql, pg_env=pg_env, audit_table=audit_table)
    ir_digest = digest_sql_result(sql=ir_sql, pg_env=pg_env, audit_table=audit_table)
    observation_set_equal = (
        None
        if audit_table is None
        else (
            runner_digest.observation_count == ir_digest.observation_count
            and runner_digest.observation_hash == ir_digest.observation_hash
        )
    )
    return {
        "experiment": experiment,
        "case": case,
        "template_id": template_id,
        "runner_sql_hash": _sha256_text(runner_sql),
        "ir_sql_hash": _sha256_text(ir_sql),
        "runner_row_count": runner_digest.row_count,
        "ir_row_count": ir_digest.row_count,
        "runner_result_hash": runner_digest.result_hash,
        "ir_result_hash": ir_digest.result_hash,
        "row_set_equal": (
            runner_digest.row_count == ir_digest.row_count
            and runner_digest.result_hash == ir_digest.result_hash
        ),
        "observation_set_equal": observation_set_equal,
        "runner_observation_count": runner_digest.observation_count,
        "ir_observation_count": ir_digest.observation_count,
        "runner_observation_hash": runner_digest.observation_hash,
        "ir_observation_hash": ir_digest.observation_hash,
    }


def _require_string(record: Mapping[str, Any], key: str, path: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}.{key} must be a non-empty string")
    return value


def _load_ir_sql_equivalence_spec(spec_path: Path) -> Mapping[str, Any]:
    with spec_path.open("r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    if not isinstance(loaded, Mapping):
        raise ValueError("IR-SQL equivalence spec root must be an object")
    if loaded.get("schema_version") != SPEC_SCHEMA_VERSION:
        raise ValueError(f"IR-SQL equivalence spec schema_version must be {SPEC_SCHEMA_VERSION}")
    return loaded


def require_complete_ir_sql_equivalence_spec(spec_path: Path) -> None:
    loaded = _load_ir_sql_equivalence_spec(spec_path)
    missing_sources = loaded.get("missing_sources", [])
    if missing_sources is None:
        missing_sources = []
    if not isinstance(missing_sources, list):
        raise ValueError("IR-SQL equivalence spec missing_sources must be a list when present")
    if missing_sources:
        examples: list[str] = []
        for item in missing_sources[:3]:
            if isinstance(item, Mapping):
                examples.append(
                    f"{item.get('experiment', '?')}/{item.get('template_id', '?')}"
                )
            else:
                examples.append(str(item))
        suffix = "" if not examples else f": {', '.join(examples)}"
        raise ValueError(
            "IR-SQL equivalence spec is incomplete; "
            f"missing_sources={len(missing_sources)}{suffix}"
        )


def _runner_sql_source_allowed(source: Any) -> bool:
    if source in ALLOWED_RUNNER_SQL_SOURCES:
        return True
    return isinstance(source, str) and "sql.execution_sql_source=planner_ir_emitted" in source


def _unbound_sql_placeholders(sql: str | None) -> tuple[str, ...]:
    if not sql:
        return ()
    return tuple(sorted(set(_UNBOUND_SQL_PLACEHOLDER_RE.findall(sql))))


def _split_projection_items(projection: str) -> tuple[str, ...]:
    items: list[str] = []
    current: list[str] = []
    depth = 0
    for char in projection:
        if char == "(":
            depth += 1
        elif char == ")" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        items.append(item)
    return tuple(items)


def _carrier_projection_columns(projection: str) -> tuple[str, ...] | None:
    if re.search(r"(^|[\s,])(?:[A-Za-z_][A-Za-z0-9_]*\.)?\*", projection):
        return None
    columns: list[str] = []
    for item in _split_projection_items(projection):
        alias_match = re.search(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", item, flags=re.IGNORECASE)
        if alias_match:
            columns.append(alias_match.group(1))
            continue
        direct_match = re.search(r"(?:^|\.)([A-Za-z_][A-Za-z0-9_]*)\s*(?:::[A-Za-z_][A-Za-z0-9_]*)?\s*$", item)
        if direct_match:
            columns.append(direct_match.group(1))
    return tuple(columns)


def _stale_carrier_projection_columns(sql: str | None) -> tuple[str, ...]:
    if not sql:
        return ()
    missing: set[str] = set()
    for cte_match in _MATERIALIZED_CTE_SELECT_RE.finditer(sql):
        cte = cte_match.group("cte")
        projected = _carrier_projection_columns(cte_match.group("projection"))
        if projected is None:
            continue
        projected_set = set(projected)
        alias_patterns = (
            rf"\bFROM\s+\(\s*SELECT\s+\*\s+FROM\s+{re.escape(cte)}\s*\)\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)",
            rf"\bFROM\s+{re.escape(cte)}\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        aliases = {
            alias
            for pattern in alias_patterns
            for alias in re.findall(pattern, sql, flags=re.IGNORECASE | re.DOTALL)
        }
        for alias in aliases:
            refs = set(re.findall(rf"\b{re.escape(alias)}\.([A-Za-z_][A-Za-z0-9_]*)\b", sql))
            missing.update(ref for ref in refs if ref not in projected_set)
    return tuple(sorted(missing))


def _runner_sql_from_record(record: Mapping[str, Any], root: Path) -> tuple[str | None, str | None]:
    for dotted in (
        "sql.ir_equivalence_runner_sql",
        "sql.runner_sql",
        "sql.execution_sql",
        "query.sql",
        "runner_sql",
    ):
        value = _get(record, dotted)
        if isinstance(value, str) and value.strip():
            return value, dotted
    if _get(record, "sql.execution_sql_source") == "planner_ir_emitted":
        ir_sql, source = _ir_sql_from_record(record)
        if ir_sql:
            return ir_sql, f"{source} via sql.execution_sql_source=planner_ir_emitted"
    return None, None


def _ir_sql_from_record(record: Mapping[str, Any]) -> tuple[str | None, str | None]:
    value = _get(record, "planner.query_plan.emitted_sql")
    if isinstance(value, str) and value.strip():
        return value, "planner.query_plan.emitted_sql"
    return None, None


def _audit_table_from_record(record: Mapping[str, Any]) -> str | None:
    udf_calls = _get(record, "runtime_audit.udf_calls")
    try:
        if int(udf_calls or 0) > 0:
            return "public.udf_audit"
    except (TypeError, ValueError):
        pass
    return None


def _requires_observation_witness(record: Mapping[str, Any]) -> bool:
    return _audit_table_from_record(record) is not None


def _compact_discovery_issues(issues: Iterable[IRSQLWitnessIssue]) -> list[dict[str, str]]:
    return [{"path": issue.path, "message": issue.message} for issue in issues]


def write_ir_sql_equivalence_spec_from_raw(
    *,
    raw_dir: Path,
    output_path: Path,
    root: Path,
    packages: Iterable[str] = DEFAULT_PACKAGES,
    required_experiments: Iterable[str] = DEFAULT_REQUIRED_EXPERIMENTS,
    setup_sql: str = "",
) -> dict[str, Any]:
    packages_tuple = tuple(packages)
    required_experiments_tuple = tuple(required_experiments)
    required, required_exemptions, discovery_issues, discovery_details = _discover_requirements(
        raw_dir,
        packages_tuple,
        required_experiments_tuple,
    )
    records_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    missing_sources: dict[tuple[str, str], dict[str, Any]] = {}

    for package in packages_tuple:
        package_path = raw_dir / package
        for path in _visible_json_paths(package_path):
            try:
                with path.open("r", encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(record, Mapping) or not _is_pass_record(record):
                continue
            experiment = _experiment(record)
            if experiment not in required_experiments_tuple:
                continue
            template_id = _template_id(record)
            key = (experiment, template_id)
            if key not in required or key in records_by_key:
                continue
            if template_id in NATIVE_RLS_TEMPLATE_IDS or _is_diagnostic_positive_control(record):
                continue
            if not _is_measured_planner_template(record):
                continue
            runner_sql, runner_source = _runner_sql_from_record(record, root)
            ir_sql, ir_source = _ir_sql_from_record(record)
            audit_table = _audit_table_from_record(record)
            requires_observation = bool(required[key].get("requires_observation_witness"))
            has_required_observation = not requires_observation or audit_table is not None
            runner_placeholders = _unbound_sql_placeholders(runner_sql)
            ir_placeholders = _unbound_sql_placeholders(ir_sql)
            runner_stale_carrier = _stale_carrier_projection_columns(runner_sql)
            ir_stale_carrier = _stale_carrier_projection_columns(ir_sql)
            has_executable_sql = (
                bool(runner_sql and ir_sql)
                and not runner_placeholders
                and not ir_placeholders
                and not runner_stale_carrier
                and not ir_stale_carrier
            )
            if has_executable_sql and has_required_observation:
                rendered: dict[str, Any] = {
                    "experiment": experiment,
                    "case": _case_id(record),
                    "template_id": template_id,
                    "runner_sql": runner_sql,
                    "ir_sql": ir_sql,
                    "source_run_id": str(record.get("run_id") or path.name),
                    "source_raw_path": str(path),
                    "runner_sql_source": runner_source,
                    "ir_sql_source": ir_source,
                }
                if audit_table:
                    rendered["audit_table"] = audit_table
                records_by_key[key] = rendered
                continue
            missing_row = {
                "experiment": experiment,
                "template_id": template_id,
                "case": _case_id(record),
                "source_run_id": str(record.get("run_id") or path.name),
                "source_raw_path": str(path),
                "missing_runner_sql": runner_sql is None or bool(runner_placeholders) or bool(runner_stale_carrier),
                "runner_sql_source": runner_source,
                "missing_ir_sql": ir_sql is None or bool(ir_placeholders) or bool(ir_stale_carrier),
                "ir_sql_source": ir_source,
                "missing_observation_witness": requires_observation and audit_table is None,
            }
            if runner_placeholders:
                missing_row["runner_sql_unbound_placeholders"] = list(runner_placeholders)
            if ir_placeholders:
                missing_row["ir_sql_unbound_placeholders"] = list(ir_placeholders)
            if runner_stale_carrier:
                missing_row["runner_sql_stale_carrier_columns"] = list(runner_stale_carrier)
            if ir_stale_carrier:
                missing_row["ir_sql_stale_carrier_columns"] = list(ir_stale_carrier)
            existing_missing = missing_sources.get(key)
            if existing_missing is None or (
                bool(existing_missing.get("missing_observation_witness")) and audit_table is not None
            ):
                missing_sources[key] = missing_row

    for key, requirement in required.items():
        if key not in records_by_key and key not in missing_sources:
            missing_sources[key] = {
                "experiment": requirement["experiment"],
                "template_id": requirement["template_id"],
                "case": (requirement.get("cases") or [""])[0],
                "source_run_id": requirement.get("representative_source_run_id"),
                "source_raw_path": None,
                "missing_runner_sql": True,
                "runner_sql_source": None,
                "missing_ir_sql": True,
                "ir_sql_source": None,
                "missing_observation_witness": bool(requirement.get("requires_observation_witness")),
            }

    exemptions = [
        {
            "experiment": item["experiment"],
            "template_id": item["template_id"],
            "reason": item["reason"],
            "representative_source_run_id": item.get("representative_source_run_id"),
            "source_run_count": item.get("source_run_count"),
        }
        for item in sorted(required_exemptions.values(), key=lambda entry: (entry["experiment"], entry["template_id"]))
    ]
    missing_source_rows = [
        missing_sources[key]
        for key in sorted(missing_sources)
        if key not in records_by_key
    ]
    payload = {
        "schema_version": SPEC_SCHEMA_VERSION,
        "setup_sql": setup_sql,
        "records": [records_by_key[key] for key in sorted(records_by_key)],
        "exemptions": exemptions,
        "missing_sources": missing_source_rows,
        "details": {
            "raw_dir": str(raw_dir),
            "root": str(root),
            "packages": discovery_details["packages"],
            "required_experiments": list(required_experiments_tuple),
            "required_witness_count": len(required),
            "required_witnesses": list(required.values()),
            "spec_record_count": len(records_by_key),
            "missing_source_count": len(missing_source_rows),
            "required_exemption_count": len(required_exemptions),
            "required_exemptions": exemptions,
            "discovery_issues": _compact_discovery_issues(discovery_issues),
            "setup_sql_embedded": bool(setup_sql.strip()),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def write_ir_sql_equivalence_witness_from_spec(
    *,
    spec_path: Path,
    output_path: Path,
    pg_env: PostgresEnv,
    allow_missing_sources: bool = False,
) -> dict[str, Any]:
    loaded = _load_ir_sql_equivalence_spec(spec_path)
    if not allow_missing_sources:
        require_complete_ir_sql_equivalence_spec(spec_path)
    setup_sql = loaded.get("setup_sql", "")
    if setup_sql is not None and not isinstance(setup_sql, str):
        raise ValueError("IR-SQL equivalence spec setup_sql must be a string when present")
    records = loaded.get("records", [])
    if not isinstance(records, list):
        raise ValueError("IR-SQL equivalence spec records must be a list")
    exemptions = loaded.get("exemptions", [])
    if not isinstance(exemptions, list):
        raise ValueError("IR-SQL equivalence spec exemptions must be a list")

    if setup_sql and setup_sql.strip():
        run_psql_command(setup_sql, pg_env)

    rendered_records: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        path = f"records[{index}]"
        if not isinstance(record, Mapping):
            raise ValueError(f"{path} must be an object")
        audit_table = record.get("audit_table")
        if audit_table is not None and not isinstance(audit_table, str):
            raise ValueError(f"{path}.audit_table must be a string or null")
        rendered_records.append(
            evaluate_ir_sql_equivalence_pair(
                experiment=_require_string(record, "experiment", path),
                case=_require_string(record, "case", path),
                template_id=_require_string(record, "template_id", path),
                runner_sql=_require_string(record, "runner_sql", path),
                ir_sql=_require_string(record, "ir_sql", path),
                pg_env=pg_env,
                audit_table=audit_table,
            )
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "spec_schema_version": SPEC_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "spec_path": str(spec_path),
        "records": rendered_records,
        "exemptions": exemptions,
        "details": {
            "record_count": len(rendered_records),
            "exemption_count": len(exemptions),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _visible_json_paths(path: Path) -> Iterable[Path]:
    if not path.exists():
        return ()
    if path.is_file():
        return (path,) if path.suffix == ".json" and not path.name.startswith("._") else ()
    return (
        item
        for item in sorted(path.rglob("*.json"))
        if item.is_file() and not item.name.startswith("._")
    )


def _get(mapping: Mapping[str, Any], dotted: str) -> Any:
    current: Any = mapping
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _is_pass_record(record: Mapping[str, Any]) -> bool:
    return record.get("status") == "pass" and record.get("run_kind") != "template_oracle_summary"


def _template_id(record: Mapping[str, Any]) -> str:
    value = _get(record, "template.template_id") or record.get("template_id")
    return "" if value in (None, "") else str(value)


def _experiment(record: Mapping[str, Any]) -> str:
    value = record.get("experiment")
    return "" if value in (None, "") else str(value)


def _case_id(record: Mapping[str, Any]) -> str:
    for key in ("query.query_id", "case.case_id", "run_id"):
        value = _get(record, key) if "." in key else record.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _has_planner_query_plan(record: Mapping[str, Any]) -> bool:
    return bool(
        _get(record, "planner.query_plan.emitted_sql")
        and _get(record, "planner.query_plan.bound_ir")
    )


def _is_measured_planner_template(record: Mapping[str, Any]) -> bool:
    if _has_planner_query_plan(record):
        return True
    if record.get("run_kind") != "template_candidate":
        return False
    if _get(record, "template_oracle.eligible_for_template_oracle") is True:
        return True
    return _get(record, "template_applicability.status") == "applicable"


def _is_diagnostic_positive_control(record: Mapping[str, Any]) -> bool:
    if _get(record, "e10_case_study.diagnostic_positive_control") is True:
        return True
    stage = str(record.get("stage") or "")
    run_kind = str(record.get("run_kind") or "")
    query_id = str(_get(record, "query.query_id") or "")
    return "diagnostic" in stage or "diagnostic" in run_kind or "diagnostic" in query_id


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _record_key(payload: Mapping[str, Any]) -> tuple[str, str]:
    return (str(payload.get("experiment") or ""), str(payload.get("template_id") or ""))


def _discover_requirements(
    raw_dir: Path,
    packages: Iterable[str],
    required_experiments: Iterable[str],
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]], list[IRSQLWitnessIssue], dict[str, Any]]:
    required_experiment_set = set(required_experiments)
    required: dict[tuple[str, str], dict[str, Any]] = {}
    required_exemptions: dict[tuple[str, str], dict[str, Any]] = {}
    issues: list[IRSQLWitnessIssue] = []
    package_details: dict[str, dict[str, Any]] = {}
    for package in packages:
        package_path = raw_dir / package
        package_info = {
            "path": str(package_path),
            "exists": package_path.exists(),
            "record_count": 0,
            "planner_record_count": 0,
            "exemptable_record_count": 0,
        }
        package_details[package] = package_info
        if not package_path.exists():
            issues.append(IRSQLWitnessIssue(str(package_path), "raw package does not exist"))
            continue
        for path in _visible_json_paths(package_path):
            package_info["record_count"] += 1
            try:
                with path.open("r", encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                issues.append(IRSQLWitnessIssue(str(path), f"failed to read raw JSON: {exc}"))
                continue
            if not isinstance(record, Mapping) or not _is_pass_record(record):
                continue
            experiment = _experiment(record)
            if experiment not in required_experiment_set:
                continue
            template_id = _template_id(record)
            if not template_id:
                continue
            key = (experiment, template_id)
            if template_id in NATIVE_RLS_TEMPLATE_IDS:
                package_info["exemptable_record_count"] += 1
                required_exemptions.setdefault(
                    key,
                    {
                        "experiment": experiment,
                        "template_id": template_id,
                        "reason": "native RLS session SQL is a baseline mode, not a planner-emitted template",
                        "source_run_ids": [],
                    },
                )["source_run_ids"].append(str(record.get("run_id") or path.name))
                continue
            if _is_diagnostic_positive_control(record):
                package_info["exemptable_record_count"] += 1
                required_exemptions.setdefault(
                    key,
                    {
                        "experiment": experiment,
                        "template_id": template_id,
                        "reason": "diagnostic positive-control SQL is intentionally outside the production planner path",
                        "source_run_ids": [],
                    },
                )["source_run_ids"].append(str(record.get("run_id") or path.name))
                continue
            if not _is_measured_planner_template(record):
                continue
            package_info["planner_record_count"] += 1
            entry = required.setdefault(
                key,
                {
                    "experiment": experiment,
                    "template_id": template_id,
                    "cases": set(),
                    "source_run_ids": [],
                    "requires_observation_witness": False,
                    "observation_cases": set(),
                },
            )
            case_id = _case_id(record)
            if case_id:
                entry["cases"].add(case_id)
            entry["source_run_ids"].append(str(record.get("run_id") or path.name))
            if _requires_observation_witness(record):
                entry["requires_observation_witness"] = True
                entry["observation_cases"].add(case_id or str(record.get("run_id") or path.name))
    rendered_required: dict[tuple[str, str], dict[str, Any]] = {}
    for key, entry in required.items():
        rendered = dict(entry)
        rendered["cases"] = sorted(entry["cases"])
        rendered["requires_observation_witness"] = bool(entry.get("requires_observation_witness"))
        rendered["observation_cases"] = sorted(entry.get("observation_cases", set()))
        source_run_ids = sorted(entry["source_run_ids"])
        rendered["source_run_count"] = len(source_run_ids)
        rendered["representative_source_run_id"] = source_run_ids[0] if source_run_ids else None
        rendered.pop("source_run_ids", None)
        rendered_required[key] = rendered
    for entry in required_exemptions.values():
        source_run_ids = sorted(entry["source_run_ids"])
        entry["source_run_count"] = len(source_run_ids)
        entry["representative_source_run_id"] = source_run_ids[0] if source_run_ids else None
        entry.pop("source_run_ids", None)
    details = {"packages": package_details}
    return rendered_required, required_exemptions, issues, details


def validate_ir_sql_equivalence(
    *,
    witness_path: Path,
    raw_dir: Path,
    packages: Iterable[str] = DEFAULT_PACKAGES,
    required_experiments: Iterable[str] = DEFAULT_REQUIRED_EXPERIMENTS,
    allow_missing_sources: bool = False,
    spec_path: Path | None = None,
) -> IRSQLWitnessReport:
    issues: list[IRSQLWitnessIssue] = []
    packages_tuple = tuple(packages)
    required_experiments_tuple = tuple(required_experiments)
    required, required_exemptions, discovery_issues, discovery_details = _discover_requirements(
        raw_dir,
        packages_tuple,
        required_experiments_tuple,
    )
    issues.extend(discovery_issues)

    witness: Mapping[str, Any] = {}
    if not witness_path.exists():
        issues.append(IRSQLWitnessIssue(str(witness_path), "IR-SQL equivalence witness JSON does not exist"))
    else:
        try:
            with witness_path.open("r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, Mapping):
                witness = loaded
            else:
                issues.append(IRSQLWitnessIssue(str(witness_path), "witness JSON root is not an object"))
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(IRSQLWitnessIssue(str(witness_path), f"failed to read witness JSON: {exc}"))

    if witness:
        if witness.get("schema_version") != SCHEMA_VERSION:
            issues.append(
                IRSQLWitnessIssue(
                    str(witness_path),
                    f"schema_version must be {SCHEMA_VERSION}",
                )
            )
    records = witness.get("records", []) if witness else []
    exemptions = witness.get("exemptions", []) if witness else []
    if witness and not isinstance(records, list):
        issues.append(IRSQLWitnessIssue(str(witness_path), "records must be a list"))
        records = []
    if witness and not isinstance(exemptions, list):
        issues.append(IRSQLWitnessIssue(str(witness_path), "exemptions must be a list"))
        exemptions = []

    missing_source_keys: set[tuple[str, str]] = set()
    documented_missing_source_count = 0
    resolved_spec_path: Path | None = spec_path
    if allow_missing_sources:
        if resolved_spec_path is None and isinstance(witness.get("spec_path"), str) and witness.get("spec_path"):
            resolved_spec_path = Path(str(witness["spec_path"]))
        if resolved_spec_path is None:
            issues.append(
                IRSQLWitnessIssue(
                    str(witness_path),
                    "allow_missing_sources requires --spec or witness.spec_path",
                )
            )
        else:
            spec_report = validate_ir_sql_equivalence_spec(
                spec_path=resolved_spec_path,
                require_complete=False,
            )
            for issue in spec_report.issues:
                issues.append(IRSQLWitnessIssue(issue.path, f"partial witness spec invalid: {issue.message}"))
            try:
                spec_payload = _load_ir_sql_equivalence_spec(resolved_spec_path)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                issues.append(IRSQLWitnessIssue(str(resolved_spec_path), f"failed to read partial witness spec: {exc}"))
            else:
                missing_sources = spec_payload.get("missing_sources", [])
                if isinstance(missing_sources, list):
                    documented_missing_source_count = len(missing_sources)
                    missing_source_keys = {
                        _record_key(item)
                        for item in missing_sources
                        if isinstance(item, Mapping) and all(_record_key(item))
                    }

    covered: dict[tuple[str, str], list[str]] = {}
    record_count = 0
    for index, item in enumerate(records):
        path = f"{witness_path}:records[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "record is not an object"))
            continue
        record_count += 1
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "record must include experiment and template_id"))
            continue
        if key in required_exemptions:
            issues.append(IRSQLWitnessIssue(path, "exempted SQL class must not be covered as planner equivalence"))
        if key not in required:
            issues.append(IRSQLWitnessIssue(path, f"record does not match a required planner template: {key[0]}/{key[1]}"))
        requires_observation = bool(required.get(key, {}).get("requires_observation_witness"))
        if not item.get("case"):
            issues.append(IRSQLWitnessIssue(path, "record must include representative case"))
        if not _sha256(item.get("runner_sql_hash")):
            issues.append(IRSQLWitnessIssue(path, "runner_sql_hash must be sha256:<64 hex>"))
        if not _sha256(item.get("ir_sql_hash")):
            issues.append(IRSQLWitnessIssue(path, "ir_sql_hash must be sha256:<64 hex>"))
        if item.get("row_set_equal") is not True:
            issues.append(IRSQLWitnessIssue(path, "row_set_equal must be true"))
        if "observation_set_equal" not in item:
            issues.append(IRSQLWitnessIssue(path, "observation_set_equal field is required"))
        elif item.get("observation_set_equal") is False:
            issues.append(IRSQLWitnessIssue(path, "observation_set_equal must not be false"))
        if requires_observation:
            if item.get("observation_set_equal") is not True:
                issues.append(IRSQLWitnessIssue(path, "observation_set_equal must be true for unsafe-UDF witness"))
            if not _sha256(item.get("runner_observation_hash")):
                issues.append(IRSQLWitnessIssue(path, "runner_observation_hash must be sha256:<64 hex>"))
            if not _sha256(item.get("ir_observation_hash")):
                issues.append(IRSQLWitnessIssue(path, "ir_observation_hash must be sha256:<64 hex>"))
        covered.setdefault(key, []).append(str(item.get("case") or f"records[{index}]"))

    missing_required = sorted(
        key
        for key in required
        if key not in covered and (not allow_missing_sources or key not in missing_source_keys)
    )
    for experiment, template_id in missing_required:
        issues.append(
            IRSQLWitnessIssue(
                str(witness_path),
                f"missing IR-SQL equivalence witness for {experiment}/{template_id}",
            )
        )

    exemption_map: dict[tuple[str, str], Mapping[str, Any]] = {}
    extra_exemptions: list[tuple[str, str]] = []
    for index, item in enumerate(exemptions):
        path = f"{witness_path}:exemptions[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "exemption is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "exemption must include experiment and template_id"))
            continue
        if not str(item.get("reason") or "").strip():
            issues.append(IRSQLWitnessIssue(path, "exemption reason is required"))
        if key in required:
            issues.append(IRSQLWitnessIssue(path, "planner template equivalence requirement cannot be exempted"))
        if key not in required_exemptions:
            issues.append(
                IRSQLWitnessIssue(
                    path,
                    f"exemption does not match a required exempt SQL class: {key[0]}/{key[1]}",
                )
            )
            extra_exemptions.append(key)
        exemption_map[key] = item
    missing_exemptions = sorted(key for key in required_exemptions if key not in exemption_map)
    for experiment, template_id in missing_exemptions:
        issues.append(
            IRSQLWitnessIssue(
                str(witness_path),
                f"missing documented exemption for {experiment}/{template_id}",
            )
        )

    details = {
        "schema_version": SCHEMA_VERSION,
        "witness_path": str(witness_path),
        "raw_dir": str(raw_dir),
        "packages": discovery_details["packages"],
        "required_experiments": list(required_experiments_tuple),
        "allow_missing_sources": allow_missing_sources,
        "spec_path": str(resolved_spec_path) if resolved_spec_path is not None else None,
        "required_witness_count": len(required),
        "observed_witness_count": record_count,
        "covered_witness_count": len([key for key in required if key in covered]),
        "documented_missing_source_count": documented_missing_source_count,
        "missing_witnesses": [
            {"experiment": experiment, "template_id": template_id}
            for experiment, template_id in missing_required
        ],
        "required_witnesses": list(required.values()),
        "required_exemption_count": len(required_exemptions),
        "missing_exemptions": [
            {"experiment": experiment, "template_id": template_id}
            for experiment, template_id in missing_exemptions
        ],
        "extra_exemptions": [
            {"experiment": experiment, "template_id": template_id}
            for experiment, template_id in sorted(set(extra_exemptions))
        ],
    }
    return IRSQLWitnessReport(tuple(issues), details)


def validate_ir_sql_equivalence_spec(
    *,
    spec_path: Path,
    require_complete: bool = True,
) -> IRSQLWitnessReport:
    issues: list[IRSQLWitnessIssue] = []
    spec: Mapping[str, Any] = {}
    try:
        loaded = _load_ir_sql_equivalence_spec(spec_path)
        spec = loaded
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        issues.append(IRSQLWitnessIssue(str(spec_path), f"failed to read IR-SQL equivalence spec: {exc}"))

    records = spec.get("records", []) if spec else []
    exemptions = spec.get("exemptions", []) if spec else []
    missing_sources = spec.get("missing_sources", []) if spec else []
    details_payload = spec.get("details", {}) if spec else {}
    if spec and not isinstance(records, list):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.records must be a list"))
        records = []
    if spec and not isinstance(exemptions, list):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.exemptions must be a list"))
        exemptions = []
    if spec and not isinstance(missing_sources, list):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.missing_sources must be a list"))
        missing_sources = []
    if spec and not isinstance(details_payload, Mapping):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.details must be an object"))
        details_payload = {}

    required_witnesses = details_payload.get("required_witnesses", []) if isinstance(details_payload, Mapping) else []
    required_exemptions_payload = (
        details_payload.get("required_exemptions", []) if isinstance(details_payload, Mapping) else []
    )
    if not isinstance(required_witnesses, list):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.details.required_witnesses must be a list"))
        required_witnesses = []
    if not isinstance(required_exemptions_payload, list):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.details.required_exemptions must be a list"))
        required_exemptions_payload = []
    required: dict[tuple[str, str], Mapping[str, Any]] = {}
    for index, item in enumerate(required_witnesses):
        path = f"{spec_path}:details.required_witnesses[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "required witness entry is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "required witness entry must include experiment and template_id"))
            continue
        required[key] = item
    required_exemptions: dict[tuple[str, str], Mapping[str, Any]] = {}
    for index, item in enumerate(required_exemptions_payload):
        path = f"{spec_path}:details.required_exemptions[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "required exemption entry is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "required exemption entry must include experiment and template_id"))
            continue
        required_exemptions[key] = item

    covered: dict[tuple[str, str], int] = {}
    duplicate_records: set[tuple[str, str]] = set()
    for index, item in enumerate(records):
        path = f"{spec_path}:records[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "spec record is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "spec record must include experiment and template_id"))
            continue
        if key in covered:
            duplicate_records.add(key)
        covered[key] = covered.get(key, 0) + 1
        if key not in required:
            issues.append(IRSQLWitnessIssue(path, f"spec record does not match required witness: {key[0]}/{key[1]}"))
        if key[1] in NATIVE_RLS_TEMPLATE_IDS:
            issues.append(IRSQLWitnessIssue(path, "native RLS baseline must be documented as an exemption, not a spec record"))
        for field in ("case", "runner_sql", "ir_sql", "source_run_id", "source_raw_path"):
            if not isinstance(item.get(field), str) or not str(item.get(field)).strip():
                issues.append(IRSQLWitnessIssue(path, f"{field} must be a non-empty string"))
        if not _runner_sql_source_allowed(item.get("runner_sql_source")):
            issues.append(IRSQLWitnessIssue(path, "runner_sql_source is not an approved explicit SQL source"))
        if item.get("ir_sql_source") != "planner.query_plan.emitted_sql":
            issues.append(IRSQLWitnessIssue(path, "ir_sql_source must be planner.query_plan.emitted_sql"))
        audit_table = item.get("audit_table")
        if audit_table is not None and (not isinstance(audit_table, str) or not audit_table.strip()):
            issues.append(IRSQLWitnessIssue(path, "audit_table must be a non-empty string when present"))
        if bool(required.get(key, {}).get("requires_observation_witness")) and not audit_table:
            issues.append(IRSQLWitnessIssue(path, "unsafe-UDF spec record must include audit_table"))

    for experiment, template_id in sorted(duplicate_records):
        issues.append(
            IRSQLWitnessIssue(
                str(spec_path),
                f"duplicate spec records for {experiment}/{template_id}",
            )
        )

    missing_source_counts: dict[tuple[str, str], int] = {}
    for item in missing_sources:
        if isinstance(item, Mapping) and all(_record_key(item)):
            key = _record_key(item)
            missing_source_counts[key] = missing_source_counts.get(key, 0) + 1
    missing_source_keys = set(missing_source_counts)
    missing_required = sorted(
        key
        for key in required
        if key not in covered and (require_complete or key not in missing_source_keys)
    )
    for experiment, template_id in missing_required:
        issues.append(
            IRSQLWitnessIssue(
                str(spec_path),
                f"missing spec record for required witness {experiment}/{template_id}",
            )
        )

    if require_complete and missing_sources:
        issues.append(
            IRSQLWitnessIssue(
                str(spec_path),
                f"IR-SQL equivalence spec has missing_sources={len(missing_sources)}",
            )
        )
    for index, item in enumerate(missing_sources):
        path = f"{spec_path}:missing_sources[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "missing_sources entry is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "missing_sources entry must include experiment and template_id"))
            continue
        if key not in required:
            issues.append(
                IRSQLWitnessIssue(
                    path,
                    f"missing_sources entry does not match required witness: {key[0]}/{key[1]}",
                )
            )
        if key in covered:
            issues.append(
                IRSQLWitnessIssue(
                    path,
                    f"missing_sources entry duplicates covered spec record: {key[0]}/{key[1]}",
                )
            )
        has_missing_reason = any(
            item.get(flag) is True
            for flag in ("missing_runner_sql", "missing_ir_sql", "missing_observation_witness")
        )
        if not has_missing_reason:
            issues.append(IRSQLWitnessIssue(path, "missing_sources entry must identify the missing source"))
    duplicate_missing_sources = sorted(key for key, count in missing_source_counts.items() if count > 1)
    for experiment, template_id in duplicate_missing_sources:
        issues.append(
            IRSQLWitnessIssue(
                str(spec_path),
                f"duplicate missing_sources entries for {experiment}/{template_id}",
            )
        )

    exemption_keys: dict[tuple[str, str], int] = {}
    for index, item in enumerate(exemptions):
        path = f"{spec_path}:exemptions[{index}]"
        if not isinstance(item, Mapping):
            issues.append(IRSQLWitnessIssue(path, "spec exemption is not an object"))
            continue
        key = _record_key(item)
        if not all(key):
            issues.append(IRSQLWitnessIssue(path, "spec exemption must include experiment and template_id"))
            continue
        exemption_keys[key] = exemption_keys.get(key, 0) + 1
        if not str(item.get("reason") or "").strip():
            issues.append(IRSQLWitnessIssue(path, "spec exemption reason is required"))
        if key in required:
            issues.append(IRSQLWitnessIssue(path, "planner template witness requirement cannot be exempted in spec"))
        if required_exemptions and key not in required_exemptions:
            issues.append(
                IRSQLWitnessIssue(
                    path,
                    f"spec exemption does not match a required exempt SQL class: {key[0]}/{key[1]}",
                )
            )
    if required_exemptions:
        missing_exemption_keys = sorted(key for key in required_exemptions if key not in exemption_keys)
        for experiment, template_id in missing_exemption_keys:
            issues.append(
                IRSQLWitnessIssue(
                    str(spec_path),
                    f"missing spec exemption for required exempt SQL class {experiment}/{template_id}",
                )
            )
    duplicate_exemptions = sorted(key for key, count in exemption_keys.items() if count > 1)
    for experiment, template_id in duplicate_exemptions:
        issues.append(
            IRSQLWitnessIssue(
                str(spec_path),
                f"duplicate spec exemptions for {experiment}/{template_id}",
            )
        )
    expected_exemption_count = details_payload.get("required_exemption_count") if isinstance(details_payload, Mapping) else None
    if expected_exemption_count is not None:
        try:
            expected_exemption_count_int = int(expected_exemption_count)
        except (TypeError, ValueError):
            issues.append(IRSQLWitnessIssue(str(spec_path), "required_exemption_count must be an integer"))
        else:
            if expected_exemption_count_int != len(exemptions):
                issues.append(
                    IRSQLWitnessIssue(
                        str(spec_path),
                        "spec exemption count does not match details.required_exemption_count",
                    )
                )

    setup_sql = spec.get("setup_sql") if spec else None
    setup_sql_embedded = bool(details_payload.get("setup_sql_embedded")) if isinstance(details_payload, Mapping) else False
    if setup_sql is not None and not isinstance(setup_sql, str):
        issues.append(IRSQLWitnessIssue(str(spec_path), "spec.setup_sql must be a string when present"))
    if setup_sql_embedded and not (isinstance(setup_sql, str) and setup_sql.strip()):
        issues.append(IRSQLWitnessIssue(str(spec_path), "setup_sql_embedded is true but setup_sql is empty"))

    details = {
        "schema_version": SPEC_SCHEMA_VERSION,
        "spec_path": str(spec_path),
        "require_complete": require_complete,
        "required_witness_count": len(required),
        "spec_record_count": len(records),
        "covered_witness_count": len([key for key in required if key in covered]),
        "missing_required_records": [
            {"experiment": experiment, "template_id": template_id}
            for experiment, template_id in missing_required
        ],
        "missing_source_count": len(missing_sources),
        "exemption_count": len(exemptions),
        "setup_sql_embedded": setup_sql_embedded,
    }
    return IRSQLWitnessReport(tuple(issues), details)
