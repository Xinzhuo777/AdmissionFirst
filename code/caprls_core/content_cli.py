"""Command-line entry point for content-boundary verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

DEFAULT_ROOT = Path(__file__).resolve().parent.parent


def _emit(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


FAMILIES = ("E2", "E3", "E10")


def _pg_env(args: argparse.Namespace, database: str):
    from caprls_core.content_psql import ContentPostgresEnv

    return ContentPostgresEnv(
        host=args.pg_host, port=args.pg_port, user=args.pg_user, database=database
    )


def _pg_env_by_family(args: argparse.Namespace):
    """Clause A — one database per family, derived from the existing `family`.

    `specs/content_cells.yaml` gains no new field, so `spec_digest` and the
    pre-registration survive the fix.
    """

    from caprls_core.content_verify import default_database_for

    envs = {}
    for family in FAMILIES:
        explicit = getattr(args, "pg_database_" + family.lower(), None)
        database = explicit or default_database_for(args.pg_database_prefix, family)
        envs[family] = _pg_env(args, database)
    return envs


def _add_pg_args(parser: argparse.ArgumentParser, *, per_family: bool) -> None:
    parser.add_argument("--pg-host", default=None)
    parser.add_argument("--pg-port", type=int, default=5432)
    parser.add_argument("--pg-user", default=None)
    if per_family:
        parser.add_argument(
            "--pg-database-prefix", default="caprls_content",
            help="per-family databases default to <prefix>_e2 / _e3 / _e10",
        )
        for family in FAMILIES:
            parser.add_argument("--pg-database-" + family.lower(), default=None)
    else:
        parser.add_argument("--pg-database", default=None)


def _cmd_offline_checks(args: argparse.Namespace) -> int:
    from caprls_core.content_offline_checks import run_all

    pg_env = None
    if args.pg_host and args.pg_user and args.pg_database:
        pg_env = _pg_env(args, args.pg_database)
    report = run_all(Path(args.root), Path(args.spec) if args.spec else None, pg_env)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with Path(args.out).open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
    if args.summary:
        print("offline checks: {}".format(report["status"].upper()))
        for name, status in sorted(report["statuses"].items()):
            print("  {:<34} {}".format(name, status))
        if report["failed"]:
            print("  failed: " + ", ".join(report["failed"]))
        if report.get("skipped"):
            print("  skipped: " + ", ".join(report["skipped"]))
            print("  NOTE: a skipped live-server check is not a green gate; "
                  "pass --pg-host/--pg-user/--pg-database before a run")
    else:
        _emit(report)
    return 0 if report["status"] in ("pass", "pass_offline_only") else 1


def _cmd_predeclare(args: argparse.Namespace) -> int:
    from caprls_core.content_predeclare import write_predeclaration

    out = Path(args.out)
    result = write_predeclaration(
        Path(args.root), out, Path(args.spec) if args.spec else None
    )
    _emit(result)
    return 0


def _cmd_fidelity_audit(args: argparse.Namespace) -> int:
    from caprls_core.content_spec_audit import run_audit

    report = run_audit(Path(args.root), Path(args.spec) if args.spec else None).to_dict()
    _emit(report)
    return 0 if report["status"] == "pass" else 1


def _cmd_falsifier(args: argparse.Namespace) -> int:
    from caprls_core.content_falsifier import run_offline

    report = run_offline(Path(args.root), Path(args.spec) if args.spec else None)
    _emit(report)
    return 0 if report["status"] == "pass" else 1


def _cmd_provision(args: argparse.Namespace) -> int:
    """Clause A — build each family's database with that family's frozen builder.

    Run **before** the package starts.  No builder ever executes against another
    family's database, because each runs against its own.
    """

    from caprls_core.content_verify import provision_family

    envs = _pg_env_by_family(args)
    wanted = [f.upper() for f in (args.family or FAMILIES)]
    results = []
    for family in wanted:
        results.append(
            provision_family(
                Path(args.root), family, envs[family],
                create_database=not args.no_create_database,
            )
        )
    _emit(
        {
            "schema": "caprls-content-provision-v1",
            "database_by_family": {f: envs[f].database for f in FAMILIES},
            "provisioned": results,
            "cross_family_ddl": False,
        }
    )
    return 0


def _cmd_content_correctness(args: argparse.Namespace) -> int:
    from caprls_core.content_verify import run_package

    if args.warmup != 0 or args.measured != 0:
        raise SystemExit(
            "content-correctness is correctness-only: warmup and measured must be 0"
        )
    summary = run_package(
        Path(args.root),
        run_id=args.run_id,
        pg_env_by_family=_pg_env_by_family(args),
        spec_path=Path(args.spec) if args.spec else None,
        predeclared_path=Path(args.predeclared) if args.predeclared else None,
        classification_path=(
            Path(args.classification) if args.classification else None
        ),
        warmup=args.warmup,
        measured=args.measured,
        only=args.only or None,
    )
    _emit(summary)
    return 0 if summary.get("package_pass") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m caprls_core.content_cli",
        description="Content-boundary correctness package (correctness-only).",
    )
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="repository root")
    parser.add_argument("--spec", default=None, help="path to specs/content_cells.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    offline = sub.add_parser(
        "offline-checks",
        help="static/offline checks; pass --pg-* to also run the live pinned-GUC gate",
    )
    offline.add_argument("--out", default=None, help="write the full JSON report here")
    offline.add_argument("--summary", action="store_true", help="print a compact table")
    _add_pg_args(offline, per_family=False)
    offline.set_defaults(func=_cmd_offline_checks)

    provision = sub.add_parser(
        "provision",
        help="build each family's database with that family's frozen builder",
    )
    provision.add_argument(
        "--family", action="append", default=[], help="E2 / E3 / E10 (default: all)"
    )
    provision.add_argument("--no-create-database", action="store_true")
    _add_pg_args(provision, per_family=True)
    provision.set_defaults(func=_cmd_provision)

    predeclare = sub.add_parser(
        "predeclare", help="write predeclared_expectations.yaml before the run"
    )
    predeclare.add_argument("--out", required=True)
    predeclare.set_defaults(func=_cmd_predeclare)

    audit = sub.add_parser("fidelity-audit", help="implementation-fidelity audit only")
    audit.set_defaults(func=_cmd_fidelity_audit)

    falsifier = sub.add_parser(
        "falsifier", help="offline byte-level recomposition falsifier only"
    )
    falsifier.set_defaults(func=_cmd_falsifier)

    run = sub.add_parser(
        "content-correctness", help="run the 52-cell package (requires a database)"
    )
    run.add_argument("--run-id", required=True, help="e.g. CONTENT_BOUNDARY_V1")
    run.add_argument("--predeclared", default=None)
    run.add_argument(
        "--classification", default=None,
        help="pre-signed selection_difference_classification.yaml (memo v2.3 clause A)",
    )
    run.add_argument("--warmup", type=int, default=0)
    run.add_argument("--measured", type=int, default=0)
    run.add_argument("--only", action="append", default=[], help="short_id or cell_id")
    _add_pg_args(run, per_family=True)
    run.set_defaults(func=_cmd_content_correctness)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
