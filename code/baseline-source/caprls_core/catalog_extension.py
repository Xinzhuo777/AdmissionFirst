"""SQL-level caprls_catalog extension witness utilities."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, Optional

from .postgres_runner import PostgresEnv, PostgresError, run_psql_file


EXTENSION_DIR = Path("sql/extensions/caprls_catalog")
CONTROL_FILE = EXTENSION_DIR / "caprls_catalog.control"
SQL_FILE = EXTENSION_DIR / "caprls_catalog--1.0.sql"
C_FILE = EXTENSION_DIR / "caprls_catalog.c"
COST_HEADER_FILE = EXTENSION_DIR / "caprls_path_cost_contract.h"
MAKEFILE = EXTENSION_DIR / "Makefile"
SMOKE_SQL_FILE = Path("sql/smoke/caprls_catalog_extension.sql")
PATH_WITNESS_SQL_FILE = Path("sql/smoke/caprls_path_witness.sql")


REQUIRED_SQL_FRAGMENTS = (
    "CREATE TABLE IF NOT EXISTS caprls_catalog.policy_catalog",
    "CREATE TABLE IF NOT EXISTS caprls_catalog.artifact_catalog",
    "declared_cardinality bigint",
    "invalid_action text",
    "CREATE TABLE IF NOT EXISTS caprls_catalog.rid_domain",
    "CREATE TABLE IF NOT EXISTS caprls_catalog.function_safety",
    "CREATE TABLE IF NOT EXISTS caprls_catalog.artifact_dependencies",
    "CREATE TABLE IF NOT EXISTS caprls_catalog.path_observation_log",
    "CREATE OR REPLACE FUNCTION caprls_catalog.caprls_assert_artifact_valid",
    "CREATE OR REPLACE FUNCTION caprls_catalog.caprls_record_path_observation",
    "CREATE OR REPLACE VIEW caprls_catalog.caprls_path_observations",
    "RAISE NOTICE",
    "P8A01",
    "P8A02",
    "P8A03",
    "fallback",
    "refresh",
    "replan",
)

REQUIRED_C_FRAGMENTS = (
    "set_rel_pathlist_hook",
    "RegisterCustomScanMethods",
    "CaprlsBarrierPath",
    "CaprlsAuthIndexPath",
    "caprls_lookup_path_witness_catalog",
    "caprls_row_query_sql",
    "caprls_load_result_rows",
    "caprls_catalog_cost_for_template",
    "caprls_path_cost_contract.h",
    "CAPRLS_PATH_COST_ARTIFACT_LOOKUP_STARTUP",
    "CAPRLS_PATH_COST_ARTIFACT_BASE_FETCH_UNIT",
    "CAPRLS_PATH_COST_BASE_SCAN_UNIT",
    "CAPRLS_PATH_COST_POLICY_EVAL_UNIT",
    "caprls_catalog.policy_catalog",
    "caprls_catalog.artifact_catalog",
    "caprls_catalog.rid_domain",
    "caprls_catalog.artifact_dependencies",
    "declared_cardinality",
    "invalid_action",
    "materialized_rel",
    "CUSTOMPATH_SUPPORT_PROJECTION",
    "caprls_catalog.enable_path_witness",
    "caprls_assert_artifact_valid",
    "caprls_record_path_observation",
    "datumCopy",
    "executing_snapshot",
    "CAPRLS Validation Snapshot",
    "ExecStoreVirtualTuple",
    "post_execution",
)

REQUIRED_PATH_WITNESS_FRAGMENTS = (
    "LOAD :'caprls_module_path'",
    "caprls_catalog.enable_path_witness",
    "CaprlsAuthIndexPath",
    "CaprlsBarrierPath",
    "CREATE TABLE ticket",
    "CREATE TABLE auth_idx_doc_ctx1",
    "CREATE TABLE auth_idx_ticket_ctx1",
    "EXPLAIN (ANALYZE, FORMAT JSON",
    "planning_time_ms",
    "planning_time_ms_by_template",
    "relation_witnesses",
    "row_hashes",
    "row_hashes_by_template",
    "validation_actions",
    "metadata_before_execution",
    "post_execution_rows",
    "stale_fallback_barrier_seen",
    "stale_reject_seen",
    "snapshot_scopes",
    "executing_snapshot",
)

PATH_WITNESS_STUB_MARKERS = (
    (
        "hard_coded_relation_document",
        "relation injection is hard-coded to document",
        'strcmp(relname, "document")',
    ),
    (
        "hard_coded_native_count_predicate",
        "native row-count query is hard-coded to document tenant_id = 1",
        "SELECT count(*) FROM document WHERE tenant_id = 1",
    ),
    (
        "virtual_null_tuple_emission",
        "CustomScan emits virtual NULL tuples instead of catalog-derived rows",
        "slot->tts_isnull[idx] = true",
    ),
    (
        "debug_guc_cost_factor",
        "path cost still uses debug GUC cost_factor instead of catalog cardinality",
        "subpath->total_cost * cost_factor",
    ),
    (
        "hard_coded_artifact_id",
        "auth-index metadata is hard-coded to auth_idx_doc_ctx1",
        "auth_idx_doc_ctx1",
    ),
)


@dataclass(frozen=True)
class CatalogExtensionAssetReport:
    ok: bool
    errors: tuple[str, ...]
    path_witness_alignment_debt: tuple[str, ...]
    control_file: Path
    sql_file: Path
    c_file: Path
    smoke_sql_file: Path
    path_witness_sql_file: Path


@dataclass(frozen=True)
class CatalogExtensionSmokeResult:
    observation_count: int
    validation_actions: tuple[str, ...]
    observations: tuple[dict, ...]
    path_witness: Mapping[str, object] | None = None


@dataclass(frozen=True)
class CatalogPathWitnessDebt:
    debt_id: str
    message: str
    marker: str
    line: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "debt_id": self.debt_id,
            "message": self.message,
            "marker": self.marker,
            "line": self.line,
        }


@dataclass(frozen=True)
class CatalogPathWitnessAlignmentReport:
    ok: bool
    asset_ok: bool
    c_file: str
    debt: tuple[CatalogPathWitnessDebt, ...]
    asset_errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "asset_ok": self.asset_ok,
            "c_file": self.c_file,
            "path_witness_alignment_debt_count": len(self.debt),
            "path_witness_alignment_debt": [item.to_dict() for item in self.debt],
            "asset_errors": list(self.asset_errors),
        }


def _first_marker_line(c_source: str, marker: str) -> int | None:
    for line_no, line in enumerate(c_source.splitlines(), start=1):
        if marker in line:
            return line_no
    return None


def _catalog_path_witness_alignment_debt_details(c_source: str) -> tuple[CatalogPathWitnessDebt, ...]:
    debt: list[CatalogPathWitnessDebt] = []
    for debt_id, message, marker in PATH_WITNESS_STUB_MARKERS:
        if marker in c_source:
            debt.append(
                CatalogPathWitnessDebt(
                    debt_id=debt_id,
                    message=message,
                    marker=marker,
                    line=_first_marker_line(c_source, marker),
                )
            )
    return tuple(debt)


def _catalog_path_witness_alignment_debt(c_source: str) -> tuple[str, ...]:
    return tuple(item.message for item in _catalog_path_witness_alignment_debt_details(c_source))


def catalog_path_witness_alignment_report(root: Path) -> CatalogPathWitnessAlignmentReport:
    asset_report = validate_catalog_extension_assets(root)
    try:
        c_source = asset_report.c_file.read_text(encoding="utf-8")
    except OSError:
        c_source = ""
    debt = _catalog_path_witness_alignment_debt_details(c_source)
    return CatalogPathWitnessAlignmentReport(
        ok=asset_report.ok and not debt,
        asset_ok=asset_report.ok,
        c_file=str(C_FILE),
        debt=debt,
        asset_errors=asset_report.errors,
    )


def validate_catalog_extension_assets(
    root: Path,
    *,
    require_catalog_driven_path_witness: bool = False,
) -> CatalogExtensionAssetReport:
    errors: List[str] = []
    control_path = root / CONTROL_FILE
    sql_path = root / SQL_FILE
    c_path = root / C_FILE
    makefile_path = root / MAKEFILE
    cost_header_path = root / COST_HEADER_FILE
    smoke_sql_path = root / SMOKE_SQL_FILE
    path_witness_sql_path = root / PATH_WITNESS_SQL_FILE

    if not control_path.exists():
        errors.append(f"missing {CONTROL_FILE}")
    else:
        control = control_path.read_text(encoding="utf-8")
        if "default_version = '1.0'" not in control:
            errors.append("caprls_catalog.control must pin default_version = '1.0'")
        if "trusted = false" not in control:
            errors.append("caprls_catalog.control must mark the extension as untrusted")

    if not sql_path.exists():
        errors.append(f"missing {SQL_FILE}")
        sql = ""
    else:
        sql = sql_path.read_text(encoding="utf-8")

    if not smoke_sql_path.exists():
        errors.append(f"missing {SMOKE_SQL_FILE}")
    else:
        smoke = smoke_sql_path.read_text(encoding="utf-8")
        for expected in ("validation_passed", "validation_fallback", "CAPRLS_RID_MISMATCH"):
            if expected not in smoke:
                errors.append(f"{SMOKE_SQL_FILE} does not exercise {expected}")

    if not c_path.exists():
        errors.append(f"missing {C_FILE}")
        c_source = ""
    else:
        c_source = c_path.read_text(encoding="utf-8")

    if not makefile_path.exists():
        errors.append(f"missing {MAKEFILE}")
    else:
        makefile = makefile_path.read_text(encoding="utf-8")
        for expected in ("MODULE_big = caprls_catalog", "OBJS = caprls_catalog.o"):
            if expected not in makefile:
                errors.append(f"{MAKEFILE} missing required fragment: {expected}")

    if not cost_header_path.exists():
        errors.append(f"missing {COST_HEADER_FILE}")
    else:
        cost_header = cost_header_path.read_text(encoding="utf-8")
        for expected in (
            "CAPRLS_PATH_COST_BASE_SCAN_UNIT",
            "CAPRLS_PATH_COST_POLICY_EVAL_UNIT",
            "CAPRLS_PATH_COST_ARTIFACT_LOOKUP_STARTUP",
            "CAPRLS_PATH_COST_ARTIFACT_BASE_FETCH_UNIT",
            "caprls_core.catalog_path_cost",
        ):
            if expected not in cost_header:
                errors.append(f"{COST_HEADER_FILE} missing required fragment: {expected}")

    if not path_witness_sql_path.exists():
        errors.append(f"missing {PATH_WITNESS_SQL_FILE}")
        path_witness_sql = ""
    else:
        path_witness_sql = path_witness_sql_path.read_text(encoding="utf-8")

    for fragment in REQUIRED_SQL_FRAGMENTS:
        if fragment not in sql:
            errors.append(f"{SQL_FILE} missing required fragment: {fragment}")
    for fragment in REQUIRED_C_FRAGMENTS:
        if fragment not in c_source:
            errors.append(f"{C_FILE} missing required fragment: {fragment}")
    for fragment in REQUIRED_PATH_WITNESS_FRAGMENTS:
        if fragment not in path_witness_sql:
            errors.append(f"{PATH_WITNESS_SQL_FILE} missing required fragment: {fragment}")

    path_witness_debt = _catalog_path_witness_alignment_debt(c_source)
    if require_catalog_driven_path_witness:
        for debt in path_witness_debt:
            errors.append(f"{C_FILE} still has path-witness alignment debt: {debt}")

    return CatalogExtensionAssetReport(
        ok=not errors,
        errors=tuple(errors),
        path_witness_alignment_debt=path_witness_debt,
        control_file=control_path,
        sql_file=sql_path,
        c_file=c_path,
        smoke_sql_file=smoke_sql_path,
        path_witness_sql_file=path_witness_sql_path,
    )


def _parse_observation_json(stdout: str) -> list[dict]:
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            payload = stripped
    if not payload:
        raise PostgresError(f"catalog extension smoke did not emit observation JSON:\n{stdout}")
    raw = json.loads(payload)
    if not isinstance(raw, list):
        raise PostgresError(f"catalog extension smoke emitted non-list JSON:\n{payload}")
    return [dict(item) for item in raw]


def _validation_actions(observations: Iterable[dict]) -> tuple[str, ...]:
    return tuple(sorted({str(item.get("validation_action")) for item in observations}))


def _parse_json_object(stdout: str) -> dict:
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise PostgresError(f"catalog path witness smoke did not emit JSON object:\n{stdout}")
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise PostgresError(f"catalog path witness smoke emitted non-object JSON:\n{payload}")
    return dict(raw)


def _build_extension_module(root: Path) -> Path:
    extension_dir = root / EXTENSION_DIR
    proc = subprocess.run(
        ["make", "-C", str(extension_dir)],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise PostgresError(
            "caprls_catalog C path witness build failed:\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    module_path = extension_dir / "caprls_catalog.dylib"
    if not module_path.exists():
        module_path = extension_dir / "caprls_catalog.so"
    if not module_path.exists():
        raise PostgresError(f"caprls_catalog build did not produce loadable module under {extension_dir}")
    return module_path.resolve()


def _validate_path_witness_payload(path_witness_payload: Mapping[str, object]) -> None:
    templates = {str(item) for item in path_witness_payload.get("templates", [])}
    missing_templates = {"CaprlsAuthIndexPath", "CaprlsBarrierPath"}.difference(templates)
    if missing_templates:
        raise PostgresError(
            "catalog path witness smoke missed template(s): "
            + ", ".join(sorted(missing_templates))
        )
    path_actions = {str(item) for item in path_witness_payload.get("validation_actions", [])}
    if "execute" not in path_actions:
        raise PostgresError("catalog path witness smoke missed execute validation action")
    if "fallback" not in path_actions:
        raise PostgresError("catalog path witness smoke missed fallback validation action")
    if "reject" not in path_actions:
        raise PostgresError("catalog path witness smoke missed reject validation action")
    if path_witness_payload.get("stale_fallback_barrier_seen") is not True:
        raise PostgresError(
            "catalog path witness did not prove stale auth-index fallback executed "
            f"through the barrier path: {path_witness_payload}"
        )
    if path_witness_payload.get("stale_reject_seen") is not True:
        raise PostgresError(
            "catalog path witness did not prove stale auth-index rejection: "
            f"{path_witness_payload}"
        )
    if (
        path_witness_payload.get("native_count") != path_witness_payload.get("auth_index_count")
        or path_witness_payload.get("native_count") != path_witness_payload.get("barrier_count")
    ):
        raise PostgresError(f"catalog path witness counts diverged: {path_witness_payload}")
    path_phases = {str(item) for item in path_witness_payload.get("observation_phases", [])}
    missing_phases = {"metadata_before_execution", "post_execution"}.difference(path_phases)
    if missing_phases:
        raise PostgresError(
            "catalog path witness missed observation phase(s): "
            + ", ".join(sorted(missing_phases))
        )
    snapshot_scopes = {str(item) for item in path_witness_payload.get("snapshot_scopes", [])}
    if "executing_snapshot" not in snapshot_scopes:
        raise PostgresError(
            "catalog path witness did not prove executing-snapshot validation scope: "
            f"{path_witness_payload}"
        )
    planning_times = path_witness_payload.get("planning_time_ms")
    if not isinstance(planning_times, Mapping):
        raise PostgresError(f"catalog path witness did not report planning_time_ms: {path_witness_payload}")
    parsed_planning_times: list[float] = []
    for key in ("native", "auth_index", "barrier"):
        try:
            parsed_planning_times.append(float(planning_times[key]))  # type: ignore[index]
        except (KeyError, TypeError, ValueError) as exc:
            raise PostgresError(
                f"catalog path witness missing numeric planning_time_ms.{key}: {path_witness_payload}"
            ) from exc
    if not any(value > 0 for value in parsed_planning_times):
        raise PostgresError(
            f"catalog path witness planning_time_ms looks like a placeholder: {planning_times}"
        )
    post_execution_rows = path_witness_payload.get("post_execution_rows")
    if not isinstance(post_execution_rows, Mapping):
        raise PostgresError(
            f"catalog path witness did not report post_execution_rows: {path_witness_payload}"
        )
    relation_witnesses = path_witness_payload.get("relation_witnesses")
    if not isinstance(relation_witnesses, Mapping) or len(relation_witnesses) < 2:
        raise PostgresError(
            "catalog path witness did not report at least two relation witnesses: "
            f"{path_witness_payload}"
        )
    row_hashes_payload = path_witness_payload.get("row_hashes")
    if not isinstance(row_hashes_payload, Mapping):
        raise PostgresError(f"catalog path witness did not report row_hashes: {path_witness_payload}")
    row_hashes_by_template = path_witness_payload.get("row_hashes_by_template")
    if not isinstance(row_hashes_by_template, Mapping):
        raise PostgresError(
            f"catalog path witness did not report row_hashes_by_template: {path_witness_payload}"
        )
    planning_times_by_template = path_witness_payload.get("planning_time_ms_by_template")
    if not isinstance(planning_times_by_template, Mapping):
        raise PostgresError(
            f"catalog path witness did not report planning_time_ms_by_template: {path_witness_payload}"
        )
    fallback_seen = False
    for relation, witness_raw in relation_witnesses.items():
        if not isinstance(witness_raw, Mapping):
            raise PostgresError(f"catalog path witness relation entry is not an object: {witness_raw}")
        policy_id = witness_raw.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id:
            raise PostgresError(f"catalog path witness relation missing policy_id: {witness_raw}")
        counts = witness_raw.get("counts")
        if not isinstance(counts, Mapping):
            raise PostgresError(f"catalog path witness relation missing counts: {witness_raw}")
        row_hashes = witness_raw.get("row_hashes")
        if not isinstance(row_hashes, Mapping):
            raise PostgresError(f"catalog path witness relation missing row_hashes: {witness_raw}")
        native_count = counts.get("native")
        keys = ["auth_index", "barrier"]
        if "fallback" in counts or "fallback" in row_hashes:
            keys.append("fallback")
            fallback_seen = True
        for key in keys:
            if counts.get(key) != native_count:
                raise PostgresError(
                    "catalog path witness count mismatch for "
                    f"{relation}: {counts}"
                )
            if row_hashes.get(key) != row_hashes.get("native"):
                raise PostgresError(
                    "catalog path witness row hash mismatch for "
                    f"{relation}: {row_hashes}"
                )
        rows_by_template = post_execution_rows.get(policy_id)
        if not isinstance(rows_by_template, Mapping):
            raise PostgresError(
                "catalog path witness post_execution_rows missing policy "
                f"{policy_id}: {post_execution_rows}"
            )
        for template in ("CaprlsAuthIndexPath", "CaprlsBarrierPath"):
            if rows_by_template.get(template) != native_count:
                raise PostgresError(
                    "catalog path witness post-execution row count diverged for "
                    f"{relation}/{template}: {rows_by_template} vs native={native_count}"
                )
        top_level_hashes = row_hashes_payload.get(str(relation))
        if top_level_hashes != row_hashes:
            raise PostgresError(
                "catalog path witness top-level row_hashes disagree with relation witness for "
                f"{relation}: {row_hashes_payload}"
            )
        template_hashes = row_hashes_by_template.get(str(relation))
        if not isinstance(template_hashes, Mapping):
            raise PostgresError(
                "catalog path witness row_hashes_by_template missing relation "
                f"{relation}: {row_hashes_by_template}"
            )
        if template_hashes.get("CaprlsAuthIndexPath") != row_hashes.get("native"):
            raise PostgresError(
                "catalog path witness auth-index template hash diverged for "
                f"{relation}: {template_hashes}"
            )
        if template_hashes.get("CaprlsBarrierPath") != row_hashes.get("native"):
            raise PostgresError(
                "catalog path witness barrier template hash diverged for "
                f"{relation}: {template_hashes}"
            )
        if (
            "fallback" in row_hashes
            and template_hashes.get("CaprlsAuthIndexPathFallback") != row_hashes.get("native")
        ):
            raise PostgresError(
                "catalog path witness fallback template hash diverged for "
                f"{relation}: {template_hashes}"
            )
        template_planning_times = planning_times_by_template.get(str(relation))
        if not isinstance(template_planning_times, Mapping):
            raise PostgresError(
                "catalog path witness planning_time_ms_by_template missing relation "
                f"{relation}: {planning_times_by_template}"
            )
        for template in ("CaprlsAuthIndexPath", "CaprlsBarrierPath"):
            try:
                float(template_planning_times[template])  # type: ignore[index]
            except (KeyError, TypeError, ValueError) as exc:
                raise PostgresError(
                    "catalog path witness missing numeric planning_time_ms_by_template "
                    f"for {relation}/{template}: {template_planning_times}"
                ) from exc
    if not fallback_seen:
        raise PostgresError(f"catalog path witness did not report a stale fallback relation: {path_witness_payload}")


def run_catalog_extension_smoke(
    root: Path,
    pg_env: PostgresEnv,
    *,
    path_witness: bool = False,
) -> CatalogExtensionSmokeResult:
    report = validate_catalog_extension_assets(root)
    if not report.ok:
        rendered = "\n".join(report.errors)
        raise PostgresError(f"caprls_catalog extension asset validation failed:\n{rendered}")

    run_psql_file(report.sql_file, pg_env)
    stdout = run_psql_file(report.smoke_sql_file, pg_env)
    observations = _parse_observation_json(stdout)
    actions = _validation_actions(observations)
    required_actions = {"execute", "fallback", "reject"}
    missing = required_actions.difference(actions)
    if missing:
        raise PostgresError(
            "catalog extension smoke missed validation action(s): "
            + ", ".join(sorted(missing))
        )

    path_witness_payload: Mapping[str, object] | None = None
    if path_witness:
        module_path = _build_extension_module(root)
        path_stdout = run_psql_file(
            report.path_witness_sql_file,
            pg_env,
            variables={"caprls_module_path": str(module_path)},
        )
        path_witness_payload = _parse_json_object(path_stdout)
        _validate_path_witness_payload(path_witness_payload)

    return CatalogExtensionSmokeResult(
        observation_count=len(observations),
        validation_actions=actions,
        observations=tuple(observations),
        path_witness=path_witness_payload,
    )
