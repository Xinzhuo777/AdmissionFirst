"""E5 reduced PostgreSQL-backed fixed-representation regret runner."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    mode_execution_order_key,
    normalize_mode_id,
)
from .e2_smoke import _build_auth_idx_sql, _clear_auth_idx_sql, _count_wrapper, _run_count_sql, _run_sql_script
from .e5_smoke import (
    REQUIRED_MODES,
    TEMPLATES,
    WITNESSES,
    E5RunResult,
    _build_mav_sql,
    _candidate_record,
    _clear_mav_sql,
    _execute_template,
    _find_mode,
    _load_manifest,
    _record,
    _query_bounds,
    _summary_record,
    _write_record,
)
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .repetitions import RepetitionRun, attach_repetition, iter_repetitions, protocol_from_manifest
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class E5MainResult:
    raw_result_paths: list[Path]
    n_points: int
    candidate_records: int
    normal_records: int
    summary_records: int
    artifact_unavailable_records: int


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E5" or manifest.get("execution_tier") != "main":
        raise PostgresError("e5-main requires an E5 main manifest")
    if manifest.get("stage") not in {"regret_reduced", "regret_full"}:
        raise PostgresError("e5-main requires stage regret_reduced or regret_full")
    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E5 main modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )
    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"E5_regret": "workloads/e5/witness_smoke.sql"}:
        raise PostgresError(f"E5 main supports only E5_regret; got {queries}")
    if not manifest.get("N"):
        raise PostgresError("E5 main requires a non-empty N list")


def _write_main_record(
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    run_id: str,
    run_kind: str,
    mode: str,
    result: E5RunResult,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    n_value: int,
    best: E5RunResult,
    amortization_q: int,
    amortization_u: int,
    output_dir: Path,
    repetition: Optional[RepetitionRun] = None,
) -> Path:
    record = _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=run_id,
        run_kind=run_kind,
        mode=mode,
        result=result,
        dataset_scale=scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        n_value=n_value,
        best_template_id=best.template_id,
        best_execution_ms=best.execution_ms,
        best_effective_ms=best.effective_ms,
        amortization_q=amortization_q,
        amortization_u=amortization_u,
        stage=stage,
        query_id="E5_regret",
        query_path="workloads/e5/witness_smoke.sql",
    )
    if repetition is not None:
        attach_repetition(record, repetition)
    return _write_record(record, output_dir)


def run_e5_main(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E5MainResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    stage = str(manifest["stage"])
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 46))
    n_values = [int(item) for item in manifest.get("N", [])]
    repetitions = protocol_from_manifest(manifest)

    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    ctx_hash = run_psql_command(
        f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
        pg_env,
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    user_id = str(context["user_id"])

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0
    artifact_unavailable_records = 0
    for n_value in n_values:
        for witness in WITNESSES:
            policy_id = witness.policy_id
            policy = _load_policy(root, policy_id)
            exact_predicate = _render_exact_predicate(
                str(policy["exact_sql_template"]),
                alias="d",
                rid_col="doc_id",
                context=context,
                relname="document",
            )
            lo, hi = _query_bounds(witness, n_value, total_rows)
            oracle_count, _ = _run_count_sql(
                _count_wrapper(
                    f"""
SELECT count(*)
FROM public.document d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
                ),
                pg_env,
            )
            authorized_rows = int(
                run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
            )
            auth_idx_artifact_id = f"e5_auth_idx_{witness.witness_id}_N{n_value}"
            mav_artifact_id = f"e5_mav_{witness.witness_id}_N{n_value}"
            _run_sql_script(_clear_auth_idx_sql(auth_idx_artifact_id), pg_env)
            _run_sql_script(_clear_mav_sql(mav_artifact_id), pg_env)
            build_ms = 0.0
            storage_bytes = 0
            artifact_cardinality = 0
            if witness.artifact_config == "auth_idx":
                started = time.monotonic()
                _run_sql_script(
                    _build_auth_idx_sql(
                        artifact_id=auth_idx_artifact_id,
                        policy_id=policy_id,
                        user_id=user_id,
                        ctx_hash=ctx_hash,
                        exact_predicate=exact_predicate,
                    ),
                    pg_env,
                )
                build_ms = (time.monotonic() - started) * 1000.0
                artifact_cardinality = int(
                    run_psql_command(
                        f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(auth_idx_artifact_id)};",
                        pg_env,
                    )
                )
                storage_bytes = artifact_cardinality * 64
            elif witness.artifact_config == "mav":
                started = time.monotonic()
                _run_sql_script(
                    _build_mav_sql(
                        artifact_id=mav_artifact_id,
                        policy_id=policy_id,
                        ctx_hash=ctx_hash,
                        exact_predicate=exact_predicate,
                    ),
                    pg_env,
                )
                build_ms = (time.monotonic() - started) * 1000.0
                artifact_cardinality = int(
                    run_psql_command(
                        "SELECT count(*) FROM public.e5_mav_authorized_document;",
                        pg_env,
                    )
                )
                storage_bytes = artifact_cardinality * 64

            for repetition in iter_repetitions(repetitions):
                candidate_results = [
                    _execute_template(
                        witness=witness,
                        template=template,
                        exact_predicate=exact_predicate,
                        lo=lo,
                        hi=hi,
                        auth_idx_artifact_id=auth_idx_artifact_id,
                        policy_id=policy_id,
                        user_id=user_id,
                        ctx_hash=ctx_hash,
                        pg_env=pg_env,
                        oracle_count=oracle_count,
                        total_rows=total_rows,
                        artifact_cardinality=artifact_cardinality,
                        build_ms=build_ms,
                        storage_bytes=storage_bytes,
                    )
                    for template in TEMPLATES
                ]
                eligible = [item for item in candidate_results if item.eligible_for_template_oracle]
                excluded = [item for item in candidate_results if not item.eligible_for_template_oracle]
                if not eligible:
                    raise PostgresError(f"E5 main witness {witness.witness_id} N={n_value} has no eligible template")
                best = min(eligible, key=lambda item: (item.effective_ms, item.template_id))
                for result in candidate_results:
                    if result.template_applicability == "artifact_unavailable":
                        artifact_unavailable_records += 1
                    raw_paths.append(
                        _write_main_record(
                            root=root,
                            manifest_path=manifest_path,
                            manifest_id=manifest_id,
                            stage=stage,
                            run_id=f"E5main_N{n_value}_{result.witness_id}_{result.template_id}",
                            run_kind="template_candidate",
                            mode="template-oracle",
                            result=result,
                            scale=scale,
                            seed=seed,
                            policy_id=policy_id,
                            context_id=context_id,
                            ctx_hash=ctx_hash,
                            pg_version=pg_version,
                            total_rows=total_rows,
                            authorized_rows=authorized_rows,
                            n_value=n_value,
                            best=best,
                            amortization_q=witness.amortization_q,
                            amortization_u=witness.amortization_u,
                            output_dir=output_dir,
                            repetition=repetition,
                        )
                    )
                    candidate_records += 1
                for mode in sorted(
                    REQUIRED_MODES - {"template-oracle"},
                    key=mode_execution_order_key,
                ):
                    # The historical E5 manifest retains this compatibility row.
                    # It is the measured TemplateOracle result, not a prospective
                    # AdmissionFirst selection, and paper-facing audits do not use it.
                    result = best if mode == ADMISSION_FIRST_MODE else _find_mode(candidate_results, mode)
                    raw_paths.append(
                        _write_main_record(
                            root=root,
                            manifest_path=manifest_path,
                            manifest_id=manifest_id,
                            stage=stage,
                            run_id=f"E5main_N{n_value}_{result.witness_id}_{mode}",
                            run_kind="normal_mode",
                            mode=mode,
                            result=result,
                            scale=scale,
                            seed=seed,
                            policy_id=policy_id,
                            context_id=context_id,
                            ctx_hash=ctx_hash,
                            pg_version=pg_version,
                            total_rows=total_rows,
                            authorized_rows=authorized_rows,
                            n_value=n_value,
                            best=best,
                            amortization_q=witness.amortization_q,
                            amortization_u=witness.amortization_u,
                            output_dir=output_dir,
                            repetition=repetition,
                        )
                    )
                    normal_records += 1
                summary = _summary_record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    witness=witness,
                    eligible=eligible,
                    excluded=excluded,
                    chosen=best,
                    dataset_scale=scale,
                    seed=seed,
                    policy_id=policy_id,
                    context_id=context_id,
                    ctx_hash=ctx_hash,
                    pg_version=pg_version,
                    total_rows=total_rows,
                    authorized_rows=authorized_rows,
                    n_value=n_value,
                    stage=stage,
                    query_id="E5_regret",
                    query_path="workloads/e5/witness_smoke.sql",
                )
                summary["run_id"] = f"E5main_N{n_value}_{witness.witness_id}_template_oracle_summary"
                summary["stage"] = stage
                attach_repetition(summary, repetition)
                raw_paths.append(_write_record(summary, output_dir))
                summary_records += 1

    return E5MainResult(
        raw_result_paths=raw_paths,
        n_points=len(n_values),
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        artifact_unavailable_records=artifact_unavailable_records,
    )
