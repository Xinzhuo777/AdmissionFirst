"""Command-line entry point for CAPRLS experiments."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .carrier_projection_audit import validate_carrier_projection_equivalence
from .catalog_extension import (
    catalog_path_witness_alignment_report,
    run_catalog_extension_smoke,
    validate_catalog_extension_assets,
)
from .certificate_replay import check_run_record_certificates_package_path
from .e10_study import run_e10_case_study, run_e10_guard_unsafe_static_witness
from .manifest_validator import ManifestValidator
from .e1_smoke import run_e1_smoke
from .e2_main import run_e2_main
from .e2_smoke import run_e2_smoke
from .e3_main import (
    e3_manifest_data_requirements_for_path,
    run_e3_main,
)
from .e3_sigmod_preview import run_e3_sigmod_preview
from .e3_rawpg_audit import validate_e3_rawpg_zero_calibration
from .e3_smoke import run_e3_smoke
from .e4_main import run_e4_main
from .e4_smoke import run_e4_smoke
from .e5_main import run_e5_main
from .e5_smoke import run_e5_smoke
from .e6a_smoke import run_e6a_smoke
from .e6b_study import run_e6b_study
from .e7_smoke import run_e7_smoke
from .e8a_smoke import run_e8a_smoke
from .e8b_study import run_e8b_study
from .e9_smoke import run_e9_smoke
from .e9_study import run_e9_study
from .e10_count_audit import validate_e10_count_sources
from .e10_diversity_audit import validate_e10_diversity
from .e2_phase_audit import validate_e2_phase_diagram
from .e3_miniplus_audit import validate_e3_miniplus
from .e4_local_greedy_audit import validate_e4_local_greedy
from .e5_fixed_regret_audit import validate_e5_fixed_regret
from .e8_cost_audit import validate_e8_cost_accounting
from .e9_overhead_audit import validate_e9_overhead
from .gate_matrix_audit import validate_gate_matrix
from .ir_sql_equivalence import DEFAULT_PACKAGES as DEFAULT_IR_SQL_EQUIVALENCE_PACKAGES
from .ir_sql_equivalence import (
    require_complete_ir_sql_equivalence_spec,
    write_ir_sql_equivalence_spec_from_raw,
    write_ir_sql_equivalence_witness_from_spec,
    validate_ir_sql_equivalence,
    validate_ir_sql_equivalence_spec,
)
from .oracle_audit import run_oracle_audit_smoke
from .postgres_runner import (
    PostgresEnv,
    PostgresError,
    run_psql_command,
    run_semantic_smoke,
    init_db,
    temporary_cluster,
)
from .reporting import (
    plot_figure,
    run_figures_small,
    summarize_experiment,
    write_claim_support_matrix,
    write_results_manifest,
)
from .result_provenance import validate_result_provenance
from .result_schema import required_schema_summary, validate_raw_run_record
from .static_verifier_evidence import validate_static_verifier_evidence
from .static_verifier_witness import write_static_verifier_template_witnesses
from .synthetic_saas import generate_synthetic_saas
from .template_smoke import run_barrier_template_smoke
from .validation_timing_audit import DEFAULT_PACKAGES as DEFAULT_VALIDATION_TIMING_PACKAGES
from .validation_timing_audit import validate_validation_timing
from .validation_timing_live_smoke import (
    validate_validation_timing_live_smoke,
    write_validation_timing_live_smoke_report,
)
from planner.core import (
    ArtifactMetadata,
    CostInputs,
    ParentRequirement,
    PlanningProblem,
    plan,
    plan_to_json,
)
from planner.verifier.static import TEMPLATE_STATIC_VERIFIERS


def _root_from_args(args: argparse.Namespace) -> Path:
    return Path(args.root).resolve()


def _print_issue(prefix: str, path: str, message: str) -> None:
    print(f"{prefix}: {path}: {message}", file=sys.stderr)


def _print_issue_sample(prefix: str, issues: tuple[object, ...], *, max_issues: int) -> None:
    limit = len(issues) if max_issues < 0 else max_issues
    for issue in issues[:limit]:
        print(f"{prefix}: {issue.path}: {issue.message}", file=sys.stderr)
    omitted = len(issues) - limit
    if omitted > 0:
        print(
            f"{prefix}: {omitted} additional issue(s) omitted; "
            "rerun with --max-issues -1 or --json for the full list",
            file=sys.stderr,
        )


def cmd_validate_manifests(args: argparse.Namespace) -> int:
    if not args.all:
        print("validate-manifests currently requires --all", file=sys.stderr)
        return 2

    validator = ManifestValidator(_root_from_args(args))
    report = validator.validate_all()

    for warning in report.warnings:
        _print_issue("warning", warning.path, warning.message)
    for error in report.errors:
        _print_issue("error", error.path, error.message)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "checked_manifests": report.checked_manifests,
                    "checked_policies": report.checked_policies,
                    "checked_modes": report.checked_modes,
                    "manifest_hashes": dict(report.manifest_hashes),
                    "errors": [issue.__dict__ for issue in report.errors],
                    "warnings": [issue.__dict__ for issue in report.warnings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif report.ok:
        print(
            "manifest validation passed: "
            f"{report.checked_manifests} experiment manifest(s), "
            f"{report.checked_policies} policy definition(s), "
            f"{report.checked_modes} mode mapping(s)"
        )
        for path, digest in sorted(report.manifest_hashes.items()):
            print(f"{digest}  {path}")

    return 0 if report.ok else 1


def cmd_manifest_hash(args: argparse.Namespace) -> int:
    from .manifest_validator import file_sha256

    root = _root_from_args(args)
    for item in args.paths:
        path = (root / item).resolve()
        try:
            rel_path = path.relative_to(root)
        except ValueError:
            rel_path = path
        if not path.exists():
            print(f"missing: {rel_path}", file=sys.stderr)
            return 1
        print(f"{file_sha256(path)}  {rel_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    run_path = Path(args.run)
    with run_path.open("r", encoding="utf-8") as fh:
        record = json.load(fh)

    issues = validate_raw_run_record(record)
    for issue in issues:
        _print_issue("error", issue.path, issue.message)

    if issues:
        return 1

    print(f"raw result schema validation passed: {run_path}")
    if args.schema_only:
        return 0

    print(
        "full static verification is not available through verify; "
        "use --schema-only or the check-cert command",
        file=sys.stderr,
    )
    return 2


def cmd_result_schema(args: argparse.Namespace) -> int:
    print(json.dumps(required_schema_summary(), indent=2, sort_keys=True))
    return 0


def cmd_check_cert(args: argparse.Namespace) -> int:
    report = check_run_record_certificates_package_path(
        Path(args.run),
        require_planner_candidates=args.require_planner_candidates,
    )
    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "certificate replay passed: "
            f"path={args.run}, "
            f"records={report.details.get('checked_record_count', 1)}, "
            f"checked={report.details.get('checked_certificate_count')}, "
            f"suppressed={report.details.get('suppressed_certificate_count')}, "
            f"sigma_mismatches={report.details.get('recorded_sigma_mismatch_count')}, "
            f"accepted={report.details.get('accepted_candidate_count')}, "
            f"rejected={report.details.get('rejected_candidate_count')}"
        )
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    artifacts = {}
    for artifact_kind in args.artifact:
        if artifact_kind == "auth_idx_keyed":
            artifacts[artifact_kind] = ArtifactMetadata(
                kind="auth_idx",
                artifact_id="cli_auth_idx_keyed",
                keyed=True,
                cardinality=args.auth_idx_cardinality,
            )
        elif artifact_kind == "auth_idx":
            artifacts[artifact_kind] = ArtifactMetadata(
                kind="auth_idx",
                artifact_id="cli_auth_idx",
                cardinality=args.auth_idx_cardinality,
            )
        elif artifact_kind == "mav":
            artifacts[artifact_kind] = ArtifactMetadata(
                kind="mav",
                artifact_id="cli_mav",
                rows=args.mav_rows,
                cardinality=args.mav_rows,
                order_keys=tuple(args.required_order),
            )
        else:
            print(f"unsupported artifact kind for planner core: {artifact_kind}", file=sys.stderr)
            return 2
    problem = PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation=args.relation,
        policy_id=args.policy,
        occurrence_id=args.occurrence_id,
        rid_col=args.rid_col,
        required_attrs=tuple(args.required_attr),
        exact_policy_safe=args.exact_policy_safe,
        supports_guard=args.supports_guard,
        has_safe_query_predicate=args.safe_query_predicate,
        artifacts=artifacts,
        parent_requirement=ParentRequirement(
            visible_columns=tuple(args.visible_column),
            required_order=tuple(args.required_order),
            transparent=not args.nontransparent_parent,
            unsafe_expression_boundary=args.unsafe_expression_boundary,
            needs_branch_lineage=args.needs_branch_lineage,
            future_rid_intersection=args.future_rid_intersection,
        ),
        cost_inputs=CostInputs(
            estimated_rows=args.estimated_rows,
            query_selectivity=args.s_q,
            auth_selectivity=args.s_auth,
            policy_eval_cost=args.policy_eval_cost,
            guard_selectivity=args.guard_selectivity,
            artifact_lookup_cost=args.artifact_lookup_cost,
            sort_cost=args.sort_cost,
        ),
        disabled_components=tuple(args.disable_component),
    )
    try:
        result = plan(problem, args.mode)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(plan_to_json(result))
    return 0


def _pg_env_from_args(args: argparse.Namespace) -> PostgresEnv:
    return PostgresEnv(
        host=args.host,
        port=args.port,
        user=args.user,
        database=args.database,
    )


def cmd_init_db(args: argparse.Namespace) -> int:
    try:
        init_db(_root_from_args(args), _pg_env_from_args(args))
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"initialized CAPRLS schema in database {args.database}")
    return 0


def cmd_pg_temp_cluster_preflight(args: argparse.Namespace) -> int:
    payload: dict[str, object] = {
        "schema_version": "caprls-pg-temp-cluster-preflight-v1",
        "database": args.database,
        "ok": False,
        "probe_sql": "SELECT 1",
    }
    try:
        with temporary_cluster(database=args.database) as pg_env:
            result = run_psql_command("SELECT 1", pg_env)
    except PostgresError as exc:
        error = str(exc)
        payload.update(
            {
                "error": error,
                "shared_memory_exhaustion": (
                    "shared-memory bootstrap failed" in error
                    or "could not create shared memory segment" in error
                    or "shmget" in error
                ),
                "remediation": (
                    "stop stale postgres processes or clear/raise system SysV shared memory limits"
                ),
            }
        )
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        print(error, file=sys.stderr)
        return 1
    payload["result"] = result.strip()
    if result.strip() != "1":
        payload.update(
            {
                "error": f"temporary PostgreSQL cluster preflight returned unexpected result: {result!r}",
                "shared_memory_exhaustion": False,
            }
        )
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        print(
            f"temporary PostgreSQL cluster preflight returned unexpected result: {result!r}",
            file=sys.stderr,
        )
        return 1
    payload.update({"ok": True, "error": None, "shared_memory_exhaustion": False})
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif not args.json:
        print(f"temporary PostgreSQL cluster preflight passed: database={args.database}")
    return 0


def cmd_catalog_extension_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    asset_report = validate_catalog_extension_assets(
        root,
        require_catalog_driven_path_witness=args.require_catalog_driven_path_witness,
    )
    for error in asset_report.errors:
        _print_issue("error", "caprls_catalog", error)
    if not asset_report.ok:
        return 1
    if args.assets_only:
        print(
            "caprls_catalog extension assets validated: "
            f"path_witness_alignment_debt={len(asset_report.path_witness_alignment_debt)}"
        )
        return 0

    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_catalog_extension_smoke(root, pg_env, path_witness=args.path_witness)
        else:
            result = run_catalog_extension_smoke(
                root,
                _pg_env_from_args(args),
                path_witness=args.path_witness,
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.path_witness_output:
        if not result.path_witness:
            print("--path-witness-output requires --path-witness", file=sys.stderr)
            return 1
        output_path = Path(args.path_witness_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(result.path_witness, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(
        "caprls_catalog extension smoke passed: "
        f"observations={result.observation_count}, "
        f"validation_actions={','.join(result.validation_actions)}"
        + (
            ", path_templates="
            + ",".join(str(item) for item in result.path_witness.get("templates", []))
            if result.path_witness
            else ""
        )
        + (
            ", path_phases="
            + ",".join(str(item) for item in result.path_witness.get("observation_phases", []))
            if result.path_witness
            else ""
        )
        + (
            ", planning_time_ms="
            + ",".join(
                f"{key}:{result.path_witness.get('planning_time_ms', {}).get(key)}"
                for key in ("native", "auth_index", "barrier")
            )
            if result.path_witness
            else ""
        )
        + (f", path_witness_output={args.path_witness_output}" if args.path_witness_output else "")
    )
    return 0


def cmd_catalog_path_witness_alignment_report(args: argparse.Namespace) -> int:
    report = catalog_path_witness_alignment_report(_root_from_args(args))
    payload = report.to_dict()
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.json:
        print(
            "catalog path witness alignment report: "
            f"asset_ok={report.asset_ok}, "
            f"path_witness_alignment_debt={len(report.debt)}, "
            f"ok={report.ok}"
        )
        for item in report.debt:
            location = f"{report.c_file}:{item.line}" if item.line is not None else report.c_file
            print(f"debt: {item.debt_id}: {location}: {item.message}")
        if args.output:
            print(f"report: {args.output}")
    if args.require_clean and not report.ok:
        return 1
    return 0


def _print_smoke_results(results: list) -> None:
    for result in results:
        print(f"{result.status.upper()} {result.test_id}: {result.details}")


def cmd_semantic_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    output_dir = Path(args.output_dir) if args.output_dir else None
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                results = run_semantic_smoke(root, pg_env, output_dir)
        else:
            results = run_semantic_smoke(root, _pg_env_from_args(args), output_dir)
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    _print_smoke_results(results)
    failed = [result for result in results if result.status != "pass"]
    if failed:
        return 1
    print(f"postgres semantic smoke passed: {len(results)} test(s)")
    return 0


def cmd_generate_data(args: argparse.Namespace) -> int:
    if args.dataset != "synthetic_saas":
        print(f"unsupported dataset: {args.dataset}", file=sys.stderr)
        return 2

    root = _root_from_args(args)
    output_dir = Path(args.output_dir) if args.output_dir else None
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = generate_synthetic_saas(
                    root=root,
                    pg_env=pg_env,
                    scale=args.scale,
                    seed=args.seed,
                    verify=args.verify,
                    output_dir=output_dir,
                )
        else:
            result = generate_synthetic_saas(
                root=root,
                pg_env=_pg_env_from_args(args),
                scale=args.scale,
                seed=args.seed,
                verify=args.verify,
                output_dir=output_dir,
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        f"generated {result.dataset_id}: "
        f"{result.table_counts.get('document', 0)} documents, "
        f"{result.table_counts.get('ticket', 0)} tickets, "
        f"{result.table_counts.get('invoice', 0)} invoices, "
        f"{result.table_counts.get('event_log', 0)} events"
    )
    for key, value in sorted(result.verification.items()):
        print(f"VERIFY {key}: {value}")
    if result.raw_result_path is not None:
        print(f"raw result: {result.raw_result_path}")
    return 0


def cmd_oracle_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    output_dir = Path(args.output_dir) if args.output_dir else None
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_oracle_audit_smoke(
                    root=root,
                    pg_env=pg_env,
                    dataset=args.dataset,
                    scale=args.scale,
                    seed=args.seed,
                    policy_id=args.policy,
                    context_id=args.context_id,
                    output_dir=output_dir,
                )
        else:
            result = run_oracle_audit_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                dataset=args.dataset,
                scale=args.scale,
                seed=args.seed,
                policy_id=args.policy,
                context_id=args.context_id,
                output_dir=output_dir,
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        f"oracle audit smoke passed for {result.context_id}: "
        f"{result.authorized_count}/{result.total_rows} authorized, "
        f"contract unauthorized observations={result.contract_unauthorized_observations}, "
        f"positive-control unauthorized observations={result.positive_unauthorized_observations}"
    )
    for test_id, path in sorted(result.raw_result_paths.items()):
        print(f"raw result {test_id}: {path}")
    return 0


def cmd_template_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    output_dir = Path(args.output_dir) if args.output_dir else None
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_barrier_template_smoke(
                    root=root,
                    pg_env=pg_env,
                    template_id=args.template,
                    dataset=args.dataset,
                    scale=args.scale,
                    seed=args.seed,
                    policy_id=args.policy,
                    context_id=args.context_id,
                    output_dir=output_dir,
                )
        else:
            result = run_barrier_template_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                template_id=args.template,
                dataset=args.dataset,
                scale=args.scale,
                seed=args.seed,
                policy_id=args.policy,
                context_id=args.context_id,
                output_dir=output_dir,
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        f"template smoke passed: {result.template_id} context={result.context_id} "
        f"rows={result.row_count} static={result.static_status} oracle={result.oracle_status}"
    )
    if result.raw_result_path is not None:
        print(f"raw result: {result.raw_result_path}")
    return 0


def cmd_e1_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        result = run_e1_smoke(
            root=root,
            manifest_path=(root / args.manifest).resolve(),
            output_dir=Path(args.output_dir),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E1 smoke passed: "
        f"admission_first_records={result.admission_first_records}, "
        f"diagnostic_records={result.diagnostic_records}, "
        f"known_invalid_rejected={result.known_invalid_rejected}, "
        f"known_valid_accepted={result.known_valid_accepted}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e2_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e2_smoke(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e2_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E2 smoke passed: "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e2_main(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e2_main(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e2_main(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E2 main passed: "
        f"grid_points={result.grid_points}, "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e3_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e3_smoke(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e3_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E3 smoke passed: "
        f"normal_records={result.normal_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e3_main(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e3_main(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e3_main(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E3 main passed: "
        f"queries={result.query_count}, "
        f"normal_records={result.normal_records}, "
        f"candidate_records={result.candidate_records}, "
        f"summary_records={result.summary_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e3_sigmod_preview(args: argparse.Namespace) -> int:
    root = _root_from_args(args)

    def run(pg_env: PostgresEnv):
        return run_e3_sigmod_preview(
            root=root,
            pg_env=pg_env,
            manifest_path=(root / args.manifest).resolve(),
            output_dir=Path(args.output_dir),
            query_ids=None if args.query is None else tuple(args.query),
            policy_ids=None if args.policy is None else tuple(args.policy),
            modes=None if args.mode is None else tuple(args.mode),
            warmup=0 if args.correctness_only else args.warmup,
            measured=0 if args.correctness_only else args.measured,
            correctness_only=args.correctness_only,
        )

    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run(pg_env)
        else:
            result = run(_pg_env_from_args(args))
    except (PostgresError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E3 SIGMOD preview complete: "
        f"cells={result.cell_count}, "
        f"passed_modes={result.passed_modes}, "
        f"correctness_failed_modes={result.correctness_failed_modes}, "
        f"execution_failed_modes={result.execution_failed_modes}, "
        f"failed_cells={result.failed_cells}, "
        f"unavailable_modes={result.unavailable_modes}"
    )
    print(f"summary: {result.summary_csv_path}")
    return (
        0
        if result.correctness_failed_modes == 0
        and result.execution_failed_modes == 0
        and result.failed_cells == 0
        else 1
    )


def cmd_validate_e3_data(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    manifest_path = (root / args.manifest).resolve()
    try:
        requirements = e3_manifest_data_requirements_for_path(root, manifest_path)
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    missing = [item for item in requirements if not item.path.exists()]
    for item in requirements:
        status = "ok" if item.path.exists() else "missing"
        print(f"{status}: {item.label}: {item.path}")
    if missing:
        print(
            f"error: E3 manifest data check failed: {len(missing)} missing file(s)",
            file=sys.stderr,
        )
        return 1
    if requirements:
        print(
            f"E3 data availability passed: {manifest_path} "
            f"({len(requirements)} required file(s))"
        )
    else:
        print(f"E3 data availability passed: {manifest_path} uses synthetic/reduced datasets")
    return 0


def cmd_e4_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        result = run_e4_smoke(
            root=root,
            manifest_path=(root / args.manifest).resolve(),
            output_dir=Path(args.output_dir),
        )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E4 smoke passed: "
        f"pairs={result.pair_count}, "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e4_main(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e4_main(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e4_main(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E4 main passed: "
        f"pairs={result.pair_count}, "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}, "
        f"contract_reject_records={result.contract_reject_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e5_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e5_smoke(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e5_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E5 smoke passed: "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e5_main(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e5_main(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e5_main(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E5 main passed: "
        f"n_points={result.n_points}, "
        f"candidate_records={result.candidate_records}, "
        f"normal_records={result.normal_records}, "
        f"summary_records={result.summary_records}, "
        f"artifact_unavailable_records={result.artifact_unavailable_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e6a_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        result = run_e6a_smoke(
            root=root,
            manifest_path=(root / args.manifest).resolve(),
            output_dir=Path(args.output_dir),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E6a smoke passed: "
        f"contract_records={result.contract_records}, "
        f"ablation_records={result.ablation_records}, "
        f"wrong_result_count={result.wrong_result_count}, "
        f"unsafe_observation_count={result.unsafe_observation_count}, "
        f"conservative_miss_count={result.conservative_miss_count}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e6b_study(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e6b_study(
                    root=root,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                    pg_env=pg_env,
                )
        else:
            result = run_e6b_study(
                root=root,
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except (PostgresError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E6b study passed: "
        f"contract_records={result.contract_records}, "
        f"ablation_records={result.ablation_records}, "
        f"wrong_result_count={result.wrong_result_count}, "
        f"unsafe_observation_count={result.unsafe_observation_count}, "
        f"missed_optimization_count={result.missed_optimization_count}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e7_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e7_smoke(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e7_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E7 smoke passed: "
        f"authorized={result.authorized_count}/{result.total_rows}, "
        f"contract_unauthorized={result.contract_unauthorized_observations}, "
        f"positive_unauthorized={result.positive_unauthorized_observations}, "
        f"guard_late_forced_unauthorized={result.guard_late_unauthorized_observations}, "
        f"mandatory_unauthorized={result.mandatory_unauthorized_observations}, "
        f"throw_client_errors={result.throw_client_errors}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e8a_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e8a_smoke(
                    root=root,
                    pg_env=pg_env,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                )
        else:
            result = run_e8a_smoke(
                root=root,
                pg_env=_pg_env_from_args(args),
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E8a smoke passed: "
        f"contract_records={result.contract_records}, "
        f"conservative_records={result.conservative_records}, "
        f"diagnostic_records={result.diagnostic_records}, "
        f"validation_failures_caught={result.validation_failures_caught}, "
        f"accepted_canonical_permutation={result.accepted_canonical_permutation}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e8b_study(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e8b_study(
                    root=root,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                    pg_env=pg_env,
                )
        else:
            result = run_e8b_study(
                root=root,
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
                pg_env=_pg_env_from_args(args),
            )
    except (PostgresError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E8b study passed: "
        f"normal_records={result.normal_records}, "
        f"contract_records={result.contract_records}, "
        f"diagnostic_wrong_results={result.diagnostic_wrong_results}, "
        f"fallback_records={result.fallback_records}, "
        f"refresh_records={result.refresh_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e9_smoke(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        result = run_e9_smoke(
            root=root,
            manifest_path=(root / args.manifest).resolve(),
            output_dir=Path(args.output_dir),
        )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E9 smoke passed: "
        f"points={result.points}, "
        f"normal_records={result.normal_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e9_study(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e9_study(
                    root=root,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                    pg_env=pg_env,
                )
        else:
            result = run_e9_study(
                root=root,
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E9 study passed: "
        f"points={result.points}, "
        f"normal_records={result.normal_records}, "
        f"max_planning_ms={result.max_planning_ms:.3f}, "
        f"max_generated_templates={result.max_generated_templates}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e10_case_study(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e10_case_study(
                    root=root,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                    pg_env=pg_env,
                )
        else:
            result = run_e10_case_study(
                root=root,
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
            )
    except (PostgresError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E10 case study passed: "
        f"queries={result.query_count}, "
        f"normal_records={result.normal_records}, "
        f"diagnostic_records={result.diagnostic_records}, "
        f"candidate_records={result.candidate_records}, "
        f"summary_records={result.summary_records}, "
        f"contract_records={result.contract_records}, "
        f"chosen_alternatives={result.chosen_alternatives}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_e10_guard_unsafe_static_witness(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    try:
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                result = run_e10_guard_unsafe_static_witness(
                    root=root,
                    manifest_path=(root / args.manifest).resolve(),
                    output_dir=Path(args.output_dir),
                    pg_env=pg_env,
                    context_id=args.context_id,
                )
        else:
            result = run_e10_guard_unsafe_static_witness(
                root=root,
                manifest_path=(root / args.manifest).resolve(),
                output_dir=Path(args.output_dir),
                pg_env=_pg_env_from_args(args),
                context_id=args.context_id,
            )
    except (PostgresError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "E10 guard+unsafe static verifier witness passed: "
        f"records={result.witness_records}"
    )
    for path in result.raw_result_paths:
        print(f"raw result: {path}")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    try:
        result = summarize_experiment(
            experiment=args.experiment,
            input_dir=Path(args.input),
            output_dir=Path(args.output),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        f"summarized {result.experiment}: {result.record_count} record(s) "
        f"to {result.output_dir}"
    )
    print(f"runs csv: {result.runs_csv}")
    print(f"cell stats csv: {result.cell_stats_csv}")
    print(f"summary json: {result.summary_json}")
    print(f"manifest hashes: {result.manifest_hashes_txt}")
    print(f"script version: {result.script_version_txt}")
    return 0


def cmd_plot(args: argparse.Namespace) -> int:
    try:
        result = plot_figure(
            figure=args.figure,
            input_path=Path(args.input),
            output_dir=Path(args.output_dir),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        f"plotted {result.figure}: {result.record_count} source row(s) "
        f"to {result.output_dir}"
    )
    print(f"figure: {result.figure_file}")
    print(f"source csv: {result.source_csv}")
    print(f"config json: {result.config_json}")
    print(f"manifest hashes: {result.manifest_hashes_txt}")
    print(f"script version: {result.script_version_txt}")
    return 0


def cmd_figures_small(args: argparse.Namespace) -> int:
    try:
        result = run_figures_small(
            raw_dir=Path(args.raw_dir),
            summary_dir=Path(args.summary_dir),
            figure_dir=Path(args.figure_dir),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        "figures-small generated: "
        f"{len(result.summaries)} summaries, {len(result.plots)} figure artifact sets"
    )
    for plot in result.plots:
        print(f"figure: {plot.figure_file}")
    return 0


def cmd_results_manifest(args: argparse.Namespace) -> int:
    result = write_results_manifest(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir),
        figure_dir=Path(args.figure_dir),
        output_path=Path(args.output),
    )
    print(
        "results manifest generated: "
        f"raw_files={result.raw_file_count}, "
        f"summary_files={result.summary_file_count}, "
        f"figure_files={result.figure_file_count}, "
        f"raw_records={result.raw_record_count}"
    )
    print(f"manifest: {result.output_path}")
    print(f"aggregate digest: {result.aggregate_digest}")
    return 0


def cmd_claim_support_matrix(args: argparse.Namespace) -> int:
    result = write_claim_support_matrix(Path(args.output_dir))
    print(
        "claim-support matrix generated: "
        f"rows={result.row_count}, output={result.output_dir}"
    )
    print(f"source csv: {result.source_csv}")
    print(f"summary json: {result.summary_json}")
    print(f"script version: {result.script_version_txt}")
    return 0


def cmd_validate_result_provenance(args: argparse.Namespace) -> int:
    issues = validate_result_provenance(Path(args.raw_dir))
    for issue in issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if issues:
        return 1
    print(f"result provenance validation passed: {args.raw_dir}")
    return 0


def cmd_validate_validation_timing(args: argparse.Namespace) -> int:
    packages = tuple(args.package or DEFAULT_VALIDATION_TIMING_PACKAGES)
    report = validate_validation_timing(
        raw_dir=Path(args.raw_dir),
        packages=packages,
        max_absolute_ms=args.max_absolute_ms,
        max_execution_fraction=args.max_execution_fraction,
        min_checked_per_package=args.min_checked_per_package,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if report.issues:
        print(
            "error: validation-timing audit failed: "
            f"packages={','.join(packages)}, "
            f"issues={len(report.issues)}, "
            f"violations={report.details.get('violation_count')}, "
            f"metadata={report.details.get('validation_metadata_violation_count')}, "
            f"timing={report.details.get('timing_violation_count')}, "
            f"oracle={report.details.get('oracle_violation_count')}, "
            f"row_count={report.details.get('row_count_violation_count')}, "
            f"result_hash={report.details.get('result_hash_violation_count')}, "
            f"coverage={report.details.get('coverage_violation_count')}",
            file=sys.stderr,
        )
        _print_issue_sample("error", report.issues, max_issues=args.max_issues)
        return 1
    if not args.json:
        print(
            "validation-timing audit passed: "
            f"packages={','.join(packages)}, "
            f"checked={report.details.get('checked_record_count')}, "
            f"skipped={report.details.get('skipped_record_count')}, "
            f"violations={report.details.get('violation_count')}, "
            f"timing={report.details.get('timing_violation_count')}, "
            f"oracle={report.details.get('oracle_violation_count')}, "
            f"row_count={report.details.get('row_count_violation_count')}, "
            f"result_hash={report.details.get('result_hash_violation_count')}, "
            f"coverage={report.details.get('coverage_violation_count')}"
        )
    return 0


def cmd_validation_timing_live_smoke(args: argparse.Namespace) -> int:
    try:
        with temporary_cluster(database=args.database) as pg_env:
            report = validate_validation_timing_live_smoke(
                pg_env,
                query_rows=args.query_rows,
                max_validation_ms=args.max_validation_ms,
                max_absolute_audit_ms=args.max_absolute_audit_ms,
                max_execution_fraction=args.max_execution_fraction,
                same_scale_slack_ms=args.same_scale_slack_ms,
                same_scale_multiplier=args.same_scale_multiplier,
            )
    except PostgresError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"validation timing live smoke failed: {exc}", file=sys.stderr)
        return 1
    if args.output:
        write_validation_timing_live_smoke_report(output_path=Path(args.output), report=report)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "validation timing live smoke passed: "
            f"validation_ms={report.details.get('validated_query_validation_ms'):.6g}, "
            f"independent_validation_ms={report.details.get('independent_validation_ms'):.6g}, "
            f"execution_ms={report.details.get('query_execution_ms'):.6g}, "
            f"audit_bound_ms={report.details.get('audit_bound_ms'):.6g}"
        )
        if args.output:
            print(f"report: {args.output}")
    return 0


def cmd_validate_carrier_projection(args: argparse.Namespace) -> int:
    report = validate_carrier_projection_equivalence()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "carrier-projection audit passed: "
            f"projection={report.details.get('projection_equivalence_passed')}/"
            f"{report.details.get('projection_checks')}, "
            f"projects={report.details.get('project_carrier_passed')}/"
            f"{report.details.get('project_carrier_checks')}"
        )
    return 0


def cmd_validate_ir_sql_equivalence(args: argparse.Namespace) -> int:
    packages = tuple(args.package or DEFAULT_IR_SQL_EQUIVALENCE_PACKAGES)
    report = validate_ir_sql_equivalence(
        witness_path=Path(args.witness),
        raw_dir=Path(args.raw_dir),
        packages=packages,
        allow_missing_sources=args.allow_missing_sources,
        spec_path=Path(args.spec) if args.spec else None,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "IR-SQL equivalence witness validation passed: "
            f"witnesses={report.details.get('covered_witness_count')}/"
            f"{report.details.get('required_witness_count')}, "
            f"missing_sources={report.details.get('documented_missing_source_count')}, "
            f"exemptions={report.details.get('required_exemption_count')}"
        )
    return 0


def cmd_validate_ir_sql_equivalence_spec(args: argparse.Namespace) -> int:
    report = validate_ir_sql_equivalence_spec(
        spec_path=Path(args.spec),
        require_complete=not args.allow_missing_sources,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "IR-SQL equivalence spec validation passed: "
            f"records={report.details.get('spec_record_count')}/"
            f"{report.details.get('required_witness_count')}, "
            f"missing_sources={report.details.get('missing_source_count')}, "
            f"exemptions={report.details.get('exemption_count')}"
        )
    return 0


def cmd_ir_sql_equivalence_spec(args: argparse.Namespace) -> int:
    try:
        setup_sql = ""
        if args.setup_sql_file:
            setup_sql = Path(args.setup_sql_file).read_text(encoding="utf-8")
        payload = write_ir_sql_equivalence_spec_from_raw(
            raw_dir=Path(args.raw_dir),
            output_path=Path(args.output),
            root=Path(args.root),
            packages=tuple(args.package or DEFAULT_IR_SQL_EQUIVALENCE_PACKAGES),
            setup_sql=setup_sql,
        )
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    details = payload.get("details", {})
    missing_count = int(details.get("missing_source_count") or 0)
    print(
        "IR-SQL equivalence spec written: "
        f"records={details.get('spec_record_count')}/"
        f"{details.get('required_witness_count')}, "
        f"missing_sources={missing_count}, "
        f"exemptions={details.get('required_exemption_count')}, "
        f"output={args.output}"
    )
    if args.require_complete and missing_count:
        return 1
    return 0


def cmd_ir_sql_equivalence_witness(args: argparse.Namespace) -> int:
    try:
        spec_path = Path(args.spec)
        output_path = Path(args.output)
        if not args.allow_missing_sources:
            require_complete_ir_sql_equivalence_spec(spec_path)
        if args.temp_cluster:
            with temporary_cluster(database=args.database) as pg_env:
                payload = write_ir_sql_equivalence_witness_from_spec(
                    spec_path=spec_path,
                    output_path=output_path,
                    pg_env=pg_env,
                    allow_missing_sources=args.allow_missing_sources,
                )
        else:
            payload = write_ir_sql_equivalence_witness_from_spec(
                spec_path=spec_path,
                output_path=output_path,
                pg_env=_pg_env_from_args(args),
                allow_missing_sources=args.allow_missing_sources,
            )
    except (ValueError, OSError, PostgresError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        "IR-SQL equivalence witness written: "
        f"records={payload.get('details', {}).get('record_count')}, "
        f"exemptions={payload.get('details', {}).get('exemption_count')}, "
        f"output={args.output}"
    )
    return 0


def cmd_validate_gate_matrix(args: argparse.Namespace) -> int:
    report = validate_gate_matrix(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir) if args.figure_dir else None,
        expected_warmup=args.expected_warmup,
        expected_measured=args.expected_measured,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        contract_counts = report.details.get("admission_first_status_counts", {})
        artifact_counts = report.details.get("artifact_validation", {}).get(
            "e8b_admission_first_action_counts", {}
        )
        print(
            "gate-matrix validation passed: "
            f"admission_first_suites={len(contract_counts)}, "
            f"e8b_artifact_actions={','.join(sorted(artifact_counts))}"
        )
    return 0


def cmd_validate_e10_diversity(args: argparse.Namespace) -> int:
    report = validate_e10_diversity(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir) if args.figure_dir else None,
        paper_path=Path(args.paper) if args.paper else None,
        raw_subdir=args.raw_subdir,
        summary_subdir=args.summary_subdir,
        figure_subdir=args.figure_subdir,
        figure_source=args.figure_source,
        expected_warmup=args.expected_warmup,
        expected_measured=args.expected_measured,
        near_miss_gap_max=args.near_miss_gap_max,
        near_miss_abs_ms_max=args.near_miss_abs_ms_max,
        expected_dataset_scale=args.expected_dataset_scale,
        expected_dataset_seed=args.expected_dataset_seed,
        min_contexts_per_case=args.min_contexts_per_case,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        family_counts = report.details.get("measured_best_family_counts", {})
        print(
            "E10 diversity validation passed: "
            f"cases={report.details.get('case_count')}, "
            f"measured_best_families={','.join(sorted(family_counts))}"
        )
    return 0


def cmd_validate_e10_counts(args: argparse.Namespace) -> int:
    report = validate_e10_count_sources(
        raw_dir=Path(args.raw_dir),
        raw_subdir=args.raw_subdir,
        project_root=Path(args.project_root),
        require_observable=not args.allow_unobservable,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "E10 count-source validation passed: "
            f"checked={report.details.get('checked_record_count')}, "
            f"unobservable={report.details.get('unobservable_policy_eval_count')}, "
            f"templates={','.join(sorted(report.details.get('checked_by_template', {})))}"
        )
    return 0


def cmd_validate_e2_phase_diagram(args: argparse.Namespace) -> int:
    required_families = None
    if args.required_winning_families:
        required_families = args.required_winning_families
    report = validate_e2_phase_diagram(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir) if args.figure_dir else None,
        manifest_path=Path(args.manifest) if args.manifest else None,
        expected_warmup=args.expected_warmup,
        expected_measured=args.expected_measured,
        min_winning_families=args.min_winning_families,
        required_winning_families=required_families,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        family_counts = report.details.get("winning_family_counts", {})
        print(
            "E2 phase-diagram validation passed: "
            f"grid_cells={len(report.details.get('manifest', {}).get('grid_points', []))}, "
            f"winning_families={','.join(sorted(family_counts))}"
        )
    return 0


def cmd_validate_e3_miniplus(args: argparse.Namespace) -> int:
    report = validate_e3_miniplus(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir) if args.figure_dir else None,
        source_path=Path(args.source) if args.source else None,
        expected_warmup=args.expected_warmup,
        expected_measured=args.expected_measured,
        slowdown_max=args.slowdown_max,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        loss_summary = report.details.get("loss_table_summary") or report.details.get("derived_loss_summary", {})
        winner_counts = loss_summary.get("winner_bucket_counts", {})
        print(
            "E3 Mini+ validation passed: "
            f"raw_records={report.details.get('raw_record_count')}, "
            f"cells={loss_summary.get('cell_count')}, "
            f"median_slowdown={loss_summary.get('admission_first_slowdown_median')}, "
            f"winner_buckets={','.join(sorted(winner_counts))}"
        )
    return 0


def cmd_validate_e4_local_greedy(args: argparse.Namespace) -> int:
    report = validate_e4_local_greedy(
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        pair_count = len(report.details.get("pair_summaries", []))
        stress = [
            str(row.get("stress_regret_or_reject"))
            for row in report.details.get("pair_summaries", [])
        ]
        print(
            "E4 local-greedy validation passed: "
            f"pairs={pair_count}, stress_evidence={','.join(stress)}"
        )
    return 0


def cmd_validate_e5_fixed_regret(args: argparse.Namespace) -> int:
    report = validate_e5_fixed_regret(
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        stress = [
            f"{row.get('theory_witness')}={row.get('max_fixed_regret')}"
            for row in report.details.get("witness_summaries", [])
        ]
        print(
            "E5 fixed-regret validation passed: "
            f"witnesses={len(stress)}, max_regrets={','.join(stress)}"
        )
    return 0


def cmd_validate_e9_overhead(args: argparse.Namespace) -> int:
    report = validate_e9_overhead(
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        figure_dir=Path(args.figure_dir),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        fig8 = report.details.get("fig8", {})
        runs = report.details.get("runs", {})
        ratios = fig8.get("planning_total_ratio_by_mode", {})
        contract = ratios.get(ADMISSION_FIRST_MODE, {})
        dominance = fig8.get("dominance_ablation", {})
        print(
            "E9 overhead validation passed: "
            f"rows={fig8.get('source_row_count')}, "
            f"max_planning_ms={fig8.get('max_planning_ms')}, "
            f"max_measured_planning_ms={runs.get('max_measured_planning_ms')}, "
            f"admission_first_ratio_max={contract.get('max')}, "
            f"dominance_pruned_max={dominance.get('admission_first_max_pruned')}, "
            f"costed_templates_saved_median={dominance.get('median_costed_templates_saved')}"
        )
    return 0


def cmd_validate_e8_cost_accounting(args: argparse.Namespace) -> int:
    report = validate_e8_cost_accounting(
        raw_dir=Path(args.raw_dir),
        summary_dir=Path(args.summary_dir) if args.summary_dir else None,
        expected_warmup=args.expected_warmup,
        expected_measured=args.expected_measured,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        stability = report.details.get("stability", {})
        class_cells = stability.get("evidence_class_cell_counts", {})
        class_records = stability.get("evidence_class_raw_record_counts", {})
        print(
            "E8 cost-accounting validation passed: "
            f"raw_records={stability.get('raw_record_count')}, "
            f"measured_records={stability.get('measured_record_count')}, "
            f"accounting_projection_cells={class_cells.get('accounting_projection')}, "
            f"gate_reject_cells={class_cells.get('gate_reject')}, "
            f"result_execution_cells={class_cells.get('result_execution')}, "
            f"accounting_projection_records={class_records.get('accounting_projection')}, "
            f"gate_reject_records={class_records.get('gate_reject')}, "
            f"result_execution_records={class_records.get('result_execution')}, "
            f"executed_wrong_results={stability.get('executed_wrong_result_count')}/"
            f"{stability.get('executed_result_denominator')}, "
            f"invalid_gate_admissions={stability.get('invalid_gate_admission_count')}, "
            "planner_choice_authority=none, performance_authority=none"
        )
    return 0


def cmd_validate_e3_rawpg_zero_calibration(args: argparse.Namespace) -> int:
    report = validate_e3_rawpg_zero_calibration(
        manifest_path=Path(args.manifest),
        raw_dir=Path(args.raw_dir) if args.raw_dir else None,
        require_promoted_injection_candidates=args.require_promoted_injection_candidates,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if report.issues:
        raw = report.details.get("raw_records", {})
        print(
            "error: E3 RawPG zero-calibration validation failed: "
            f"issues={len(report.issues)}, "
            f"records={raw.get('record_count', '<skipped>')}, "
            f"diagnostics={raw.get('candidate_diagnostic_count', '<skipped>')}, "
            f"dominance={raw.get('dominance_violation_count', '<skipped>')}/"
            f"{raw.get('dominance_checked_record_count', '<skipped>')}, "
            f"promoted_injection_required={raw.get('promoted_injection_candidate_requirement', False)}",
            file=sys.stderr,
        )
        _print_issue_sample("error", report.issues, max_issues=args.max_issues)
        return 1
    if not args.json:
        raw = report.details.get("raw_records", {})
        print(
            "E3 RawPG zero-calibration validation passed: "
            f"records={raw.get('record_count', '<skipped>')}, "
            f"diagnostics={raw.get('candidate_diagnostic_count', '<skipped>')}, "
            f"dominance={raw.get('dominance_violation_count', '<skipped>')}/"
            f"{raw.get('dominance_checked_record_count', '<skipped>')}, "
            f"promoted_injection_required={raw.get('promoted_injection_candidate_requirement', False)}"
        )
    return 0


def cmd_validate_static_verifier_evidence(args: argparse.Namespace) -> int:
    required_template_ids = list(args.required_template_id or [])
    if args.require_registered_template_coverage:
        required_template_ids.extend(sorted(TEMPLATE_STATIC_VERIFIERS))
    report = validate_static_verifier_evidence(
        tuple(Path(path) for path in args.paths),
        require_explain_path=not args.allow_missing_explain,
        require_guard_unsafe_witness=args.require_guard_unsafe_witness,
        required_template_ids=tuple(required_template_ids),
    )
    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    for issue in report.issues:
        print(f"error: {issue.path}: {issue.message}", file=sys.stderr)
    if report.issues:
        return 1
    if not args.json:
        print(
            "static verifier evidence validation passed: "
            f"records={report.details.get('record_count')}, "
            f"pass_records={report.details.get('pass_record_count')}, "
            f"checked={report.details.get('checked_static_verifier_count')}, "
            f"explain_artifacts={report.details.get('checked_explain_artifact_count')}, "
            f"guard_unsafe_witnesses={report.details.get('guard_unsafe_witness_count')}, "
            f"templates={len(report.details.get('template_evidence_counts', {}))}"
        )
    return 0


def cmd_static_verifier_template_witness(args: argparse.Namespace) -> int:
    try:
        result = write_static_verifier_template_witnesses(
            root=Path(args.root).resolve(),
            output_dir=Path(args.output_dir),
        )
    except Exception as exc:
        print(f"static verifier template witness generation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "static verifier template witness generated: "
        f"output_dir={result.output_dir}, records={result.witness_records}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caprls")
    parser.add_argument("--root", default=".", help="repository root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-manifests")
    validate.add_argument("--all", action="store_true", help="validate all manifests")
    validate.add_argument("--json", action="store_true", help="emit machine-readable report")
    validate.set_defaults(func=cmd_validate_manifests)

    manifest_hash = subparsers.add_parser("manifest-hash")
    manifest_hash.add_argument("paths", nargs="+")
    manifest_hash.set_defaults(func=cmd_manifest_hash)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--run", required=True)
    verify.add_argument("--schema-only", action="store_true")
    verify.set_defaults(func=cmd_verify)

    result_schema = subparsers.add_parser("result-schema")
    result_schema.set_defaults(func=cmd_result_schema)

    check_cert = subparsers.add_parser("check-cert")
    check_cert.add_argument("run")
    check_cert.add_argument("--require-planner-candidates", action="store_true")
    check_cert.add_argument("--json", action="store_true")
    check_cert.set_defaults(func=cmd_check_cert)

    plan_cmd = subparsers.add_parser("plan")
    plan_cmd.add_argument("--mode", required=True)
    plan_cmd.add_argument("--relation", default="document")
    plan_cmd.add_argument("--policy", default="tenant_group")
    plan_cmd.add_argument("--occurrence-id", default="occ_1")
    plan_cmd.add_argument("--rid-col", default="doc_id")
    plan_cmd.add_argument("--estimated-rows", type=int, default=100000)
    plan_cmd.add_argument("--s-auth", type=float, default=0.1)
    plan_cmd.add_argument("--s-q", type=float, default=1.0)
    plan_cmd.add_argument("--policy-eval-cost", type=float, default=0.003)
    plan_cmd.add_argument("--guard-selectivity", type=float, default=0.25)
    plan_cmd.add_argument("--artifact-lookup-cost", type=float, default=0.2)
    plan_cmd.add_argument("--sort-cost", type=float, default=0.0)
    plan_cmd.add_argument("--auth-idx-cardinality", type=int, default=1000)
    plan_cmd.add_argument("--mav-rows", type=int, default=1000)
    plan_cmd.add_argument("--artifact", action="append", default=[])
    plan_cmd.add_argument("--required-attr", action="append", default=[])
    plan_cmd.add_argument("--visible-column", action="append", default=[])
    plan_cmd.add_argument("--required-order", action="append", default=[])
    plan_cmd.add_argument("--exact-policy-safe", action="store_true")
    plan_cmd.add_argument("--supports-guard", action="store_true")
    plan_cmd.add_argument("--safe-query-predicate", action="store_true")
    plan_cmd.add_argument("--nontransparent-parent", action="store_true")
    plan_cmd.add_argument("--unsafe-expression-boundary", action="store_true")
    plan_cmd.add_argument("--needs-branch-lineage", action="store_true")
    plan_cmd.add_argument("--future-rid-intersection", action="store_true")
    plan_cmd.add_argument("--disable-component", action="append", default=[])
    plan_cmd.set_defaults(func=cmd_plan)

    init = subparsers.add_parser("init-db")
    init.add_argument("--config", default="configs/pg_smoke.yaml")
    init.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    init.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    init.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    init.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    init.set_defaults(func=cmd_init_db)

    pg_preflight = subparsers.add_parser("pg-temp-cluster-preflight")
    pg_preflight.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_preflight"))
    pg_preflight.add_argument("--output")
    pg_preflight.add_argument("--json", action="store_true")
    pg_preflight.set_defaults(func=cmd_pg_temp_cluster_preflight)

    catalog_extension = subparsers.add_parser("catalog-extension-smoke")
    catalog_extension.add_argument("--assets-only", action="store_true")
    catalog_extension.add_argument("--path-witness", action="store_true")
    catalog_extension.add_argument("--path-witness-output")
    catalog_extension.add_argument("--require-catalog-driven-path-witness", action="store_true")
    catalog_extension.add_argument("--temp-cluster", action="store_true")
    catalog_extension.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    catalog_extension.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    catalog_extension.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    catalog_extension.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    catalog_extension.set_defaults(func=cmd_catalog_extension_smoke)

    catalog_path_alignment = subparsers.add_parser("catalog-path-witness-alignment-report")
    catalog_path_alignment.add_argument("--output")
    catalog_path_alignment.add_argument("--require-clean", action="store_true")
    catalog_path_alignment.add_argument("--json", action="store_true")
    catalog_path_alignment.set_defaults(func=cmd_catalog_path_witness_alignment_report)

    semantic = subparsers.add_parser("semantic-smoke")
    semantic.add_argument("--temp-cluster", action="store_true")
    semantic.add_argument("--output-dir", default=None)
    semantic.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    semantic.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    semantic.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    semantic.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    semantic.set_defaults(func=cmd_semantic_smoke)

    generate = subparsers.add_parser("generate-data")
    generate.add_argument("--dataset", required=True)
    generate.add_argument("--scale", required=True)
    generate.add_argument("--seed", type=int, required=True)
    generate.add_argument("--verify", action="store_true")
    generate.add_argument("--temp-cluster", action="store_true")
    generate.add_argument("--output-dir", default=None)
    generate.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    generate.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    generate.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    generate.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    generate.set_defaults(func=cmd_generate_data)

    oracle = subparsers.add_parser("oracle-smoke")
    oracle.add_argument("--dataset", required=True)
    oracle.add_argument("--scale", required=True)
    oracle.add_argument("--seed", type=int, required=True)
    oracle.add_argument("--policy", required=True)
    oracle.add_argument("--context-id", required=True)
    oracle.add_argument("--temp-cluster", action="store_true")
    oracle.add_argument("--output-dir", default=None)
    oracle.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    oracle.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    oracle.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    oracle.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    oracle.set_defaults(func=cmd_oracle_smoke)

    template = subparsers.add_parser("template-smoke")
    template.add_argument("--template", required=True)
    template.add_argument("--dataset", required=True)
    template.add_argument("--scale", required=True)
    template.add_argument("--seed", type=int, required=True)
    template.add_argument("--policy", required=True)
    template.add_argument("--context-id", required=True)
    template.add_argument("--temp-cluster", action="store_true")
    template.add_argument("--output-dir", default=None)
    template.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    template.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    template.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    template.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    template.set_defaults(func=cmd_template_smoke)

    e1_smoke = subparsers.add_parser("e1-smoke")
    e1_smoke.add_argument("--manifest", required=True)
    e1_smoke.add_argument("--output-dir", required=True)
    e1_smoke.set_defaults(func=cmd_e1_smoke)

    e2_smoke = subparsers.add_parser("e2-smoke")
    e2_smoke.add_argument("--manifest", required=True)
    e2_smoke.add_argument("--output-dir", required=True)
    e2_smoke.add_argument("--temp-cluster", action="store_true")
    e2_smoke.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e2_smoke.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e2_smoke.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e2_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e2_smoke.set_defaults(func=cmd_e2_smoke)

    e2_main = subparsers.add_parser("e2-main")
    e2_main.add_argument("--manifest", required=True)
    e2_main.add_argument("--output-dir", required=True)
    e2_main.add_argument("--temp-cluster", action="store_true")
    e2_main.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e2_main.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e2_main.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e2_main.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e2_main.set_defaults(func=cmd_e2_main)

    e3_smoke = subparsers.add_parser("e3-smoke")
    e3_smoke.add_argument("--manifest", required=True)
    e3_smoke.add_argument("--output-dir", required=True)
    e3_smoke.add_argument("--temp-cluster", action="store_true")
    e3_smoke.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e3_smoke.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e3_smoke.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e3_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e3_smoke.set_defaults(func=cmd_e3_smoke)

    e3_main = subparsers.add_parser("e3-main")
    e3_main.add_argument("--manifest", required=True)
    e3_main.add_argument("--output-dir", required=True)
    e3_main.add_argument("--temp-cluster", action="store_true")
    e3_main.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e3_main.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e3_main.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e3_main.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e3_main.set_defaults(func=cmd_e3_main)

    e3_preview = subparsers.add_parser("e3-sigmod-preview")
    e3_preview.add_argument(
        "--manifest",
        default="manifests/experiments/v3/e3_standard_reduced.yaml",
    )
    e3_preview.add_argument(
        "--output-dir",
        default="results/v3/raw/E3_SIGMOD_PREVIEW",
    )
    e3_preview.add_argument("--query", action="append")
    e3_preview.add_argument("--policy", action="append")
    e3_preview.add_argument("--mode", action="append")
    e3_preview.add_argument("--warmup", type=int, default=5)
    e3_preview.add_argument("--measured", type=int, default=10)
    e3_preview.add_argument("--correctness-only", action="store_true")
    e3_preview.add_argument("--temp-cluster", action="store_true")
    e3_preview.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e3_preview.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e3_preview.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e3_preview.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e3_preview.set_defaults(func=cmd_e3_sigmod_preview)

    e3_data = subparsers.add_parser("validate-e3-data")
    e3_data.add_argument("--manifest", required=True)
    e3_data.set_defaults(func=cmd_validate_e3_data)

    e4_smoke = subparsers.add_parser("e4-smoke")
    e4_smoke.add_argument("--manifest", required=True)
    e4_smoke.add_argument("--output-dir", required=True)
    e4_smoke.set_defaults(func=cmd_e4_smoke)

    e4_main = subparsers.add_parser("e4-main")
    e4_main.add_argument("--manifest", required=True)
    e4_main.add_argument("--output-dir", required=True)
    e4_main.add_argument("--temp-cluster", action="store_true")
    e4_main.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e4_main.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e4_main.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e4_main.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e4_main.set_defaults(func=cmd_e4_main)

    e5_smoke = subparsers.add_parser("e5-smoke")
    e5_smoke.add_argument("--manifest", required=True)
    e5_smoke.add_argument("--output-dir", required=True)
    e5_smoke.add_argument("--temp-cluster", action="store_true")
    e5_smoke.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e5_smoke.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e5_smoke.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e5_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e5_smoke.set_defaults(func=cmd_e5_smoke)

    e5_main = subparsers.add_parser("e5-main")
    e5_main.add_argument("--manifest", required=True)
    e5_main.add_argument("--output-dir", required=True)
    e5_main.add_argument("--temp-cluster", action="store_true")
    e5_main.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e5_main.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e5_main.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e5_main.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e5_main.set_defaults(func=cmd_e5_main)

    e6a_smoke = subparsers.add_parser("e6a-smoke")
    e6a_smoke.add_argument("--manifest", required=True)
    e6a_smoke.add_argument("--output-dir", required=True)
    e6a_smoke.set_defaults(func=cmd_e6a_smoke)

    e6b_study = subparsers.add_parser("e6b-study")
    e6b_study.add_argument("--manifest", required=True)
    e6b_study.add_argument("--output-dir", required=True)
    e6b_study.add_argument("--temp-cluster", action="store_true")
    e6b_study.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e6b_study.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e6b_study.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e6b_study.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e6b_study.set_defaults(func=cmd_e6b_study)

    e7_smoke = subparsers.add_parser("e7-smoke")
    e7_smoke.add_argument("--manifest", required=True)
    e7_smoke.add_argument("--output-dir", required=True)
    e7_smoke.add_argument("--temp-cluster", action="store_true")
    e7_smoke.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e7_smoke.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e7_smoke.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e7_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e7_smoke.set_defaults(func=cmd_e7_smoke)

    e8a_smoke = subparsers.add_parser("e8a-smoke")
    e8a_smoke.add_argument("--manifest", required=True)
    e8a_smoke.add_argument("--output-dir", required=True)
    e8a_smoke.add_argument("--temp-cluster", action="store_true")
    e8a_smoke.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e8a_smoke.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e8a_smoke.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e8a_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e8a_smoke.set_defaults(func=cmd_e8a_smoke)

    e8b_study = subparsers.add_parser("e8b-study")
    e8b_study.add_argument("--manifest", required=True)
    e8b_study.add_argument("--output-dir", required=True)
    e8b_study.add_argument("--temp-cluster", action="store_true")
    e8b_study.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e8b_study.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e8b_study.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e8b_study.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e8b_study.set_defaults(func=cmd_e8b_study)

    e9_smoke = subparsers.add_parser("e9-smoke")
    e9_smoke.add_argument("--manifest", required=True)
    e9_smoke.add_argument("--output-dir", required=True)
    e9_smoke.set_defaults(func=cmd_e9_smoke)

    e9_study = subparsers.add_parser("e9-study")
    e9_study.add_argument("--manifest", required=True)
    e9_study.add_argument("--output-dir", required=True)
    e9_study.add_argument("--temp-cluster", action="store_true")
    e9_study.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e9_study.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e9_study.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e9_study.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e9_study.set_defaults(func=cmd_e9_study)

    e10_case_study = subparsers.add_parser("e10-case-study")
    e10_case_study.add_argument("--manifest", required=True)
    e10_case_study.add_argument("--output-dir", required=True)
    e10_case_study.add_argument("--temp-cluster", action="store_true")
    e10_case_study.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e10_case_study.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e10_case_study.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e10_case_study.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e10_case_study.set_defaults(func=cmd_e10_case_study)

    e10_guard_witness = subparsers.add_parser("e10-guard-unsafe-static-witness")
    e10_guard_witness.add_argument("--manifest", required=True)
    e10_guard_witness.add_argument("--output-dir", required=True)
    e10_guard_witness.add_argument("--context-id", default="ctx_000001")
    e10_guard_witness.add_argument("--temp-cluster", action="store_true")
    e10_guard_witness.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    e10_guard_witness.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    e10_guard_witness.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    e10_guard_witness.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_smoke"))
    e10_guard_witness.set_defaults(func=cmd_e10_guard_unsafe_static_witness)

    static_verifier_witness = subparsers.add_parser("static-verifier-template-witness")
    static_verifier_witness.add_argument("--output-dir", required=True)
    static_verifier_witness.set_defaults(func=cmd_static_verifier_template_witness)

    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("--experiment", required=True)
    summarize.add_argument("--input", required=True)
    summarize.add_argument("--output", required=True)
    summarize.set_defaults(func=cmd_summarize)

    plot = subparsers.add_parser("plot")
    plot.add_argument("--figure", required=True)
    plot.add_argument("--input", required=True)
    plot.add_argument("--output-dir", default="results/figures")
    plot.set_defaults(func=cmd_plot)

    figures_small = subparsers.add_parser("figures-small")
    figures_small.add_argument("--raw-dir", default="results/raw")
    figures_small.add_argument("--summary-dir", default="results/summarized")
    figures_small.add_argument("--figure-dir", default="results/figures")
    figures_small.set_defaults(func=cmd_figures_small)

    results_manifest = subparsers.add_parser("results-manifest")
    results_manifest.add_argument("--raw-dir", default="results/raw")
    results_manifest.add_argument("--summary-dir", default="results/summarized")
    results_manifest.add_argument("--figure-dir", default="results/figures")
    results_manifest.add_argument("--output", default="results/artifact_manifest.json")
    results_manifest.set_defaults(func=cmd_results_manifest)

    claim_support = subparsers.add_parser("claim-support-matrix")
    claim_support.add_argument("--output-dir", default="results/summarized/CLAIM_SUPPORT")
    claim_support.set_defaults(func=cmd_claim_support_matrix)

    result_provenance = subparsers.add_parser("validate-result-provenance")
    result_provenance.add_argument("--raw-dir", default="results/raw")
    result_provenance.set_defaults(func=cmd_validate_result_provenance)

    static_evidence = subparsers.add_parser("validate-static-verifier-evidence")
    static_evidence.add_argument("paths", nargs="+")
    static_evidence.add_argument("--allow-missing-explain", action="store_true")
    static_evidence.add_argument("--require-guard-unsafe-witness", action="store_true")
    static_evidence.add_argument("--required-template-id", action="append", default=[])
    static_evidence.add_argument("--require-registered-template-coverage", action="store_true")
    static_evidence.add_argument("--json", action="store_true")
    static_evidence.set_defaults(func=cmd_validate_static_verifier_evidence)

    validation_timing = subparsers.add_parser("validate-validation-timing")
    validation_timing.add_argument("--raw-dir", default="results/raw")
    validation_timing.add_argument(
        "--package",
        action="append",
        help="Raw package under --raw-dir to audit; may be repeated. Defaults cover R-7 affected packages.",
    )
    validation_timing.add_argument("--max-absolute-ms", type=float, default=50.0)
    validation_timing.add_argument("--max-execution-fraction", type=float, default=0.30)
    validation_timing.add_argument("--min-checked-per-package", type=int, default=1)
    validation_timing.add_argument(
        "--max-issues",
        type=int,
        default=20,
        help="Maximum individual issues to print on stderr; use -1 for all. JSON output remains complete.",
    )
    validation_timing.add_argument("--json", action="store_true")
    validation_timing.set_defaults(func=cmd_validate_validation_timing)

    validation_live_smoke = subparsers.add_parser("validation-timing-live-smoke")
    validation_live_smoke.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_validation_smoke"))
    validation_live_smoke.add_argument("--query-rows", type=int, default=200_000)
    validation_live_smoke.add_argument("--max-validation-ms", type=float, default=100.0)
    validation_live_smoke.add_argument("--max-absolute-audit-ms", type=float, default=50.0)
    validation_live_smoke.add_argument("--max-execution-fraction", type=float, default=0.30)
    validation_live_smoke.add_argument("--same-scale-slack-ms", type=float, default=25.0)
    validation_live_smoke.add_argument("--same-scale-multiplier", type=float, default=10.0)
    validation_live_smoke.add_argument("--output", default="results/analysis/validation_timing_live_smoke_v1.json")
    validation_live_smoke.add_argument("--json", action="store_true")
    validation_live_smoke.set_defaults(func=cmd_validation_timing_live_smoke)

    carrier_projection = subparsers.add_parser("validate-carrier-projection")
    carrier_projection.add_argument("--json", action="store_true")
    carrier_projection.set_defaults(func=cmd_validate_carrier_projection)

    ir_sql_spec = subparsers.add_parser("ir-sql-equivalence-spec")
    ir_sql_spec.add_argument("--raw-dir", default="results/raw")
    ir_sql_spec.add_argument("--root", default=".")
    ir_sql_spec.add_argument(
        "--package",
        action="append",
        help=(
            "Raw package under --raw-dir used to derive representative witness specs; "
            "may be repeated."
        ),
    )
    ir_sql_spec.add_argument("--setup-sql-file")
    ir_sql_spec.add_argument(
        "--output",
        default="results/analysis/ir_sql_equivalence_witness_spec_v1.json",
    )
    ir_sql_spec.add_argument("--require-complete", action="store_true")
    ir_sql_spec.set_defaults(func=cmd_ir_sql_equivalence_spec)

    ir_sql_witness = subparsers.add_parser("ir-sql-equivalence-witness")
    ir_sql_witness.add_argument(
        "--spec",
        required=True,
        help="IR-SQL equivalence witness spec JSON.",
    )
    ir_sql_witness.add_argument(
        "--output",
        default="results/analysis/ir_sql_equivalence_witness_v1.json",
    )
    ir_sql_witness.add_argument("--temp-cluster", action="store_true")
    ir_sql_witness.add_argument(
        "--allow-missing-sources",
        action="store_true",
        help="Debug only: allow witness generation from an incomplete spec.",
    )
    ir_sql_witness.add_argument("--host", default=os.environ.get("PGHOST", "/tmp"))
    ir_sql_witness.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    ir_sql_witness.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    ir_sql_witness.add_argument("--database", default=os.environ.get("PGDATABASE", "caprls_ir_sql_equivalence"))
    ir_sql_witness.set_defaults(func=cmd_ir_sql_equivalence_witness)

    ir_sql_spec_validate = subparsers.add_parser("validate-ir-sql-equivalence-spec")
    ir_sql_spec_validate.add_argument(
        "--spec",
        default="results/analysis/ir_sql_equivalence_witness_spec_v1.json",
    )
    ir_sql_spec_validate.add_argument(
        "--allow-missing-sources",
        action="store_true",
        help="Allow incomplete specs while still validating structure and documented gaps.",
    )
    ir_sql_spec_validate.add_argument("--json", action="store_true")
    ir_sql_spec_validate.set_defaults(func=cmd_validate_ir_sql_equivalence_spec)

    ir_sql_equivalence = subparsers.add_parser("validate-ir-sql-equivalence")
    ir_sql_equivalence.add_argument(
        "--witness",
        default="results/analysis/ir_sql_equivalence_witness_v1.json",
    )
    ir_sql_equivalence.add_argument(
        "--spec",
        help=(
            "IR-SQL equivalence spec used to document missing sources when "
            "--allow-missing-sources is set. Defaults to witness.spec_path when present."
        ),
    )
    ir_sql_equivalence.add_argument("--raw-dir", default="results/raw")
    ir_sql_equivalence.add_argument(
        "--package",
        action="append",
        help=(
            "Raw package under --raw-dir used to derive required planner-template coverage; "
            "may be repeated."
        ),
    )
    ir_sql_equivalence.add_argument(
        "--allow-missing-sources",
        action="store_true",
        help="Allow documented missing witness coverage while still validating covered records strictly.",
    )
    ir_sql_equivalence.add_argument("--json", action="store_true")
    ir_sql_equivalence.set_defaults(func=cmd_validate_ir_sql_equivalence)

    gate_matrix = subparsers.add_parser("validate-gate-matrix")
    gate_matrix.add_argument("--raw-dir", default="results/raw")
    gate_matrix.add_argument("--summary-dir", default="results/summarized")
    gate_matrix.add_argument("--figure-dir", default="results/figures")
    gate_matrix.add_argument("--expected-warmup", type=int, default=5)
    gate_matrix.add_argument("--expected-measured", type=int, default=10)
    gate_matrix.add_argument("--json", action="store_true")
    gate_matrix.set_defaults(func=cmd_validate_gate_matrix)

    e10_diversity = subparsers.add_parser("validate-e10-diversity")
    e10_diversity.add_argument("--raw-dir", default="results/raw")
    e10_diversity.add_argument("--summary-dir", default="results/summarized")
    e10_diversity.add_argument("--figure-dir", default="results/figures")
    e10_diversity.add_argument(
        "--paper",
        help="optional paper file for a separate presentation-level table check",
    )
    e10_diversity.add_argument("--raw-subdir", default="SIGMOD_CURRENT_E10")
    e10_diversity.add_argument("--summary-subdir", default="SIGMOD_CURRENT_E10")
    e10_diversity.add_argument("--figure-subdir", default="tab2_e10_diversity")
    e10_diversity.add_argument("--figure-source")
    e10_diversity.add_argument("--expected-warmup", type=int, default=5)
    e10_diversity.add_argument("--expected-measured", type=int, default=10)
    e10_diversity.add_argument("--near-miss-gap-max", type=float, default=1.10)
    e10_diversity.add_argument("--near-miss-abs-ms-max", type=float, default=0.050)
    e10_diversity.add_argument("--expected-dataset-scale")
    e10_diversity.add_argument("--expected-dataset-seed", type=int)
    e10_diversity.add_argument("--min-contexts-per-case", type=int)
    e10_diversity.add_argument("--json", action="store_true")
    e10_diversity.set_defaults(func=cmd_validate_e10_diversity)

    e10_counts = subparsers.add_parser("validate-e10-counts")
    e10_counts.add_argument("--raw-dir", default="results/raw")
    e10_counts.add_argument("--raw-subdir", default="SIGMOD_CURRENT_E10")
    e10_counts.add_argument("--project-root", default=".")
    e10_counts.add_argument("--allow-unobservable", action="store_true")
    e10_counts.add_argument("--json", action="store_true")
    e10_counts.set_defaults(func=cmd_validate_e10_counts)

    e2_phase = subparsers.add_parser("validate-e2-phase-diagram")
    e2_phase.add_argument("--raw-dir", default="results/raw")
    e2_phase.add_argument("--summary-dir", default="results/summarized")
    e2_phase.add_argument("--figure-dir", default="results/figures")
    e2_phase.add_argument("--manifest", default="manifests/experiments/e2_alternative_matrix_reduced.yaml")
    e2_phase.add_argument("--expected-warmup", type=int, default=5)
    e2_phase.add_argument("--expected-measured", type=int, default=10)
    e2_phase.add_argument("--min-winning-families", type=int, default=0)
    e2_phase.add_argument(
        "--required-winning-families",
        default="",
    )
    e2_phase.add_argument("--json", action="store_true")
    e2_phase.set_defaults(func=cmd_validate_e2_phase_diagram)

    e3_miniplus = subparsers.add_parser("validate-e3-miniplus")
    e3_miniplus.add_argument("--raw-dir", default="results/raw")
    e3_miniplus.add_argument("--summary-dir", default="results/summarized")
    e3_miniplus.add_argument("--figure-dir", default="results/figures")
    e3_miniplus.add_argument("--source", default="caprls_core/e3_main.py")
    e3_miniplus.add_argument("--expected-warmup", type=int, default=5)
    e3_miniplus.add_argument("--expected-measured", type=int, default=10)
    e3_miniplus.add_argument("--slowdown-max", type=float, default=1.20)
    e3_miniplus.add_argument("--json", action="store_true")
    e3_miniplus.set_defaults(func=cmd_validate_e3_miniplus)

    e3_rawpg = subparsers.add_parser("validate-e3-rawpg-zero-calibration")
    e3_rawpg.add_argument("--manifest", default="manifests/experiments/e3_standard_sf1_rawpg.yaml")
    e3_rawpg.add_argument("--raw-dir", default="results/raw/E3_SF1_RAWPG_V1")
    e3_rawpg.add_argument("--require-promoted-injection-candidates", action="store_true")
    e3_rawpg.add_argument(
        "--max-issues",
        type=int,
        default=20,
        help="Maximum individual issues to print on stderr; use -1 for all. JSON output remains complete.",
    )
    e3_rawpg.add_argument("--json", action="store_true")
    e3_rawpg.set_defaults(func=cmd_validate_e3_rawpg_zero_calibration)

    e4_local_greedy = subparsers.add_parser("validate-e4-local-greedy")
    e4_local_greedy.add_argument("--summary-dir", default="results/summarized")
    e4_local_greedy.add_argument("--figure-dir", default="results/figures")
    e4_local_greedy.add_argument("--json", action="store_true")
    e4_local_greedy.set_defaults(func=cmd_validate_e4_local_greedy)

    e5_fixed_regret = subparsers.add_parser("validate-e5-fixed-regret")
    e5_fixed_regret.add_argument("--summary-dir", default="results/summarized")
    e5_fixed_regret.add_argument("--figure-dir", default="results/figures")
    e5_fixed_regret.add_argument("--json", action="store_true")
    e5_fixed_regret.set_defaults(func=cmd_validate_e5_fixed_regret)

    e8_cost = subparsers.add_parser("validate-e8-cost-accounting")
    e8_cost.add_argument("--raw-dir", default="results/raw")
    e8_cost.add_argument("--summary-dir", default="results/summarized")
    e8_cost.add_argument("--expected-warmup", type=int, default=5)
    e8_cost.add_argument("--expected-measured", type=int, default=10)
    e8_cost.add_argument("--json", action="store_true")
    e8_cost.set_defaults(func=cmd_validate_e8_cost_accounting)

    e9_overhead = subparsers.add_parser("validate-e9-overhead")
    e9_overhead.add_argument("--summary-dir", default="results/summarized")
    e9_overhead.add_argument("--figure-dir", default="results/figures")
    e9_overhead.add_argument("--json", action="store_true")
    e9_overhead.set_defaults(func=cmd_validate_e9_overhead)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
