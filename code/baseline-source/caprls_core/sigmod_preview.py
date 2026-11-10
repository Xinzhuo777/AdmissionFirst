"""Build the paper correctness authority from ordinary experiment results.

The authority deliberately uses the ordinary experiment outputs: the
AdmissionFirst rows in ``runs.csv``, their referenced raw JSON records, the
matching ``cell_stats.csv`` rows, and each experiment summary.  It does not
depend on a freeze, launcher, or promotion bundle.
"""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import argparse
import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class SigmodPreviewError(ValueError):
    """The existing evidence cannot support the paper correctness authority."""


@dataclass(frozen=True)
class FamilySpec:
    family: str
    experiment: str
    expected_cells: int
    check_kind: str
    scope: str
    warmup_repetitions: int = 5
    measured_repetitions: int = 10


DEFAULT_FAMILIES: Tuple[FamilySpec, ...] = (
    FamilySpec(
        "E2_PROTOCOL",
        "E2",
        8,
        "independent_scalar_count_equality",
        "Independent scalar-count equality.",
    ),
    FamilySpec(
        "E3_SF1_RAWPG_V1",
        "E3",
        33,
        "independent_output_row_count_equality",
        "Independent output-row-count equality; not full row, value, or order equality.",
    ),
    FamilySpec(
        "SIGMOD_CURRENT_E10",
        "E10",
        11,
        "independent_scalar_count_equality",
        "Independent scalar-count equality.",
    ),
)

# New authority writes are isolated from the retained paper authority.  The
# latter remains readable through ``sigmod_release`` for reproducible release
# reports, but must never be an implicit writer destination.
DEFAULT_OUTPUT_DIR = Path("results/v3/summarized/SIGMOD_CURRENT")
DEFAULT_E3_CANONICAL_RECEIPTS = Path(
    "results/raw/E3_CANONICAL_CORRECTNESS_V1/summary.csv"
)
CORRECTNESS_CELLS_FILENAME = "correctness_cells.csv"
CORRECTNESS_SUMMARY_FILENAME = "correctness_summary.json"

CORE_DIMENSIONS: Tuple[str, ...] = (
    "experiment",
    "dataset_name",
    "dataset_scale",
    "dataset_seed",
    "query_id",
    "policy_id",
    "context_id",
)

RUN_REQUIRED_COLUMNS = frozenset(
    {
        "raw_path",
        "run_id",
        "manifest_id",
        "manifest_hash",
        "experiment",
        "run_kind",
        "dataset_name",
        "dataset_scale",
        "dataset_seed",
        "query_id",
        "policy_id",
        "context_id",
        "mode",
        "template_id",
        "status",
        "oracle_status",
        "runtime_audit_status",
        "unauthorized_observations",
        "result_hash",
        "git_commit",
        "measurement_phase",
        "measurement_iteration",
        "measurement_warmup_repetitions",
        "measurement_measured_repetitions",
    }
)

CELL_REQUIRED_COLUMNS = frozenset(
    {
        "experiment",
        "dataset_name",
        "dataset_scale",
        "dataset_seed",
        "query_id",
        "policy_id",
        "context_id",
        "mode",
        "sample_count",
        "warmup_count",
        "total_record_count",
        "manifest_hashes",
        "required_warmup_repetitions",
        "required_measured_repetitions",
        "protocol_status",
        "status_counts",
        "observed_template_ids",
    }
)

E3_CANONICAL_REQUIRED_COLUMNS = frozenset(
    {
        "manifest_id",
        "manifest_sha256",
        "git_commit",
        "query_id",
        "workload",
        "dataset_scale",
        "seed",
        "policy_id",
        "mode",
        "template_id",
        "admission_first_selected_template",
        "status",
        "row_count",
        "reference_row_count",
        "result_digest",
        "reference_digest",
        "actual_only_rows",
        "reference_only_rows",
        "ordered_sequence_match",
        "measurement_protocol",
    }
)

E3_CANONICAL_IDENTITY_FIELDS: Tuple[str, ...] = (
    "query_id",
    "workload",
    "dataset_scale",
    "seed",
    "policy_id",
)

OUTPUT_COLUMNS: Tuple[str, ...] = (
    "family",
    "check_kind",
    "scope",
    "cell_id",
    "experiment",
    "dataset_name",
    "dataset_scale",
    "dataset_seed",
    "query_id",
    "policy_id",
    "context_id",
    "cell_parameters_json",
    "template_ids",
    "manifest_ids",
    "manifest_hashes",
    "git_commits",
    "warmup_records",
    "measured_records",
    "total_records",
    "status_pass_records",
    "oracle_match_records",
    "runtime_audit_pass_records",
    "unauthorized_observations",
    "nonempty_result_hash_records",
    "raw_records_checked",
    "protocol_status",
    "correctness_status",
    "canonical_content_receipt_status",
    "canonical_content_receipt_source",
    "canonical_content_source_commit",
    "canonical_content_manifest_sha256",
    "canonical_content_measurement_protocol",
    "canonical_content_template_id",
    "canonical_content_row_count",
    "canonical_content_digest",
    "canonical_content_actual_only_rows",
    "canonical_content_reference_only_rows",
    "canonical_content_ordered_sequence_match",
)


@dataclass(frozen=True)
class PreviewResult:
    cells_csv: Path
    summary_json: Path
    summary: Mapping[str, Any]


def _fail(message: str) -> None:
    raise SigmodPreviewError(message)


def _output_reference(repo_root: Path, path: Path) -> str:
    """Return a repository-relative output path when one is available."""

    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _input_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path, required: Iterable[str]) -> Tuple[List[Dict[str, str]], Tuple[str, ...]]:
    if not path.is_file():
        _fail("missing source CSV: {}".format(path))
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = tuple(reader.fieldnames or ())
        missing = sorted(set(required) - set(fields))
        if missing:
            _fail("{} is missing columns: {}".format(path, ", ".join(missing)))
        return [dict(row) for row in reader], fields


def _read_json(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        _fail("missing source JSON: {}".format(path))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SigmodPreviewError("invalid JSON at {}: {}".format(path, exc)) from exc
    if not isinstance(payload, Mapping):
        _fail("JSON root must be an object: {}".format(path))
    return payload


def _as_int(value: Any, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise SigmodPreviewError("{} must be an integer, got {!r}".format(label, value)) from exc


def _nested(payload: Mapping[str, Any], path: Sequence[str], source: Path) -> Any:
    current: Any = payload
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            _fail("{} is missing {}".format(source, ".".join(path)))
        current = current[part]
    return current


def _expect(actual: Any, expected: Any, label: str, source: Path) -> None:
    if actual != expected:
        _fail("{} has {}={!r}; expected {!r}".format(source, label, actual, expected))


def _parameter_columns(*field_sets: Sequence[str]) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {
                field
                for fields in field_sets
                for field in fields
                if field.startswith("param_")
            }
        )
    )


def _cell_key(row: Mapping[str, str], parameter_columns: Sequence[str]) -> Tuple[str, ...]:
    return tuple(str(row.get(field, "")) for field in CORE_DIMENSIONS + tuple(parameter_columns))


def _cell_parameters(row: Mapping[str, str], parameter_columns: Sequence[str]) -> Dict[str, str]:
    return {
        field[len("param_") :]: str(row.get(field, ""))
        for field in parameter_columns
        if str(row.get(field, "")) != ""
    }


def _cell_id(
    family: str,
    row: Mapping[str, str],
    parameter_columns: Sequence[str],
) -> str:
    parts = [
        family,
        "query={}".format(row["query_id"]),
        "policy={}".format(row["policy_id"]),
        "context={}".format(row["context_id"]),
    ]
    parts.extend(
        "{}={}".format(name, value)
        for name, value in _cell_parameters(row, parameter_columns).items()
    )
    return "|".join(parts)


def _json_list(value: str, label: str, source: Path) -> List[str]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SigmodPreviewError("{} has invalid {} JSON".format(source, label)) from exc
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        _fail("{} {} must be a JSON string list".format(source, label))
    return payload


def _sha256_digest(value: str, label: str, source: Path) -> str:
    digest = value.strip()
    payload = digest[len("sha256:") :] if digest.startswith("sha256:") else ""
    if len(payload) != 64 or any(char not in "0123456789abcdef" for char in payload):
        _fail("{} has invalid {}={!r}".format(source, label, value))
    return digest


def _git_commit(value: str, label: str, source: Path) -> str:
    commit = value.strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        _fail("{} has invalid {}={!r}".format(source, label, value))
    return commit


def _csv_bool(value: str, label: str, source: Path) -> bool:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        _fail("{} has invalid {}={!r}".format(source, label, value))
    return normalized == "true"


def _ordinary_e3_receipt_identity(row: Mapping[str, Any]) -> Tuple[str, ...]:
    return (
        str(row["query_id"]),
        str(row["dataset_name"]),
        str(row["dataset_scale"]),
        str(row["dataset_seed"]),
        str(row["policy_id"]),
    )


def _canonical_e3_receipt_identity(row: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(str(row[field]) for field in E3_CANONICAL_IDENTITY_FIELDS)


def _identity_text(identity: Sequence[str]) -> str:
    return ",".join(
        "{}={}".format(field, value)
        for field, value in zip(E3_CANONICAL_IDENTITY_FIELDS, identity)
    )


def _validate_e3_canonical_receipts(
    repo_root: Path,
    receipt_path: Path,
    authority_rows: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Attach one canonical full-row content receipt to every ordinary E3 cell."""

    source = _input_path(repo_root, receipt_path)
    receipt_rows, _ = _read_csv(source, E3_CANONICAL_REQUIRED_COLUMNS)
    selected_with_lines = [
        (row_number, row)
        for row_number, row in enumerate(receipt_rows, start=2)
        if normalize_mode_id(str(row["mode"])) == ADMISSION_FIRST_MODE
    ]

    expected_e3_rows = [
        row for row in authority_rows if row["experiment"] == "E3"
    ]
    if len(expected_e3_rows) != 33:
        _fail(
            "ordinary E3 authority has {} cells; canonical content authority requires 33".format(
                len(expected_e3_rows)
            )
        )

    ordinary_manifest_hashes = {
        manifest_hash
        for row in expected_e3_rows
        for manifest_hash in str(row["manifest_hashes"]).split(";")
        if manifest_hash
    }
    if len(ordinary_manifest_hashes) != 1:
        _fail(
            "ordinary E3 authority identifies {} manifest hashes; expected exactly one".format(
                len(ordinary_manifest_hashes)
            )
        )
    ordinary_manifest_hash = _sha256_digest(
        next(iter(ordinary_manifest_hashes)),
        "ordinary E3 manifest hash",
        source,
    )

    expected_by_identity: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for row in expected_e3_rows:
        identity = _ordinary_e3_receipt_identity(row)
        if identity in expected_by_identity:
            _fail(
                "ordinary E3 authority duplicates canonical identity {}".format(
                    _identity_text(identity)
                )
            )
        expected_by_identity[identity] = row

    receipt_by_identity: Dict[Tuple[str, ...], Tuple[int, Dict[str, str]]] = {}
    for row_number, row in selected_with_lines:
        identity = _canonical_e3_receipt_identity(row)
        if identity in receipt_by_identity:
            _fail(
                "{}:{} duplicates AdmissionFirst canonical identity {}".format(
                    source, row_number, _identity_text(identity)
                )
            )
        receipt_by_identity[identity] = (row_number, row)

    if len(selected_with_lines) != 33:
        _fail(
            "{} has {} AdmissionFirst canonical content receipts; expected exactly 33".format(
                source, len(selected_with_lines)
            )
        )

    expected_identities = set(expected_by_identity)
    observed_identities = set(receipt_by_identity)
    if observed_identities != expected_identities:
        missing = sorted(expected_identities - observed_identities)
        unexpected = sorted(observed_identities - expected_identities)
        details = []
        if missing:
            details.append("missing {}".format(_identity_text(missing[0])))
        if unexpected:
            details.append("unexpected {}".format(_identity_text(unexpected[0])))
        _fail(
            "{} canonical receipt identity mismatch ({})".format(
                source, "; ".join(details)
            )
        )

    ordered_matches = 0
    manifest_ids = set()
    dataset_scales = set()
    seeds = set()
    git_commits = set()
    canonical_manifest_hashes = set()
    canonical_templates = set()
    for identity in sorted(expected_identities):
        row_number, receipt = receipt_by_identity[identity]
        location = Path("{}:{}".format(source, row_number))
        authority_row = expected_by_identity[identity]
        template_id = receipt["template_id"].strip()
        selected_template = receipt["admission_first_selected_template"].strip()
        if not template_id or not selected_template:
            _fail("{} has an empty canonical template identity".format(location))
        if template_id != selected_template:
            _fail(
                "{} template_id={!r} differs from admission_first_selected_template={!r}".format(
                    location, template_id, selected_template
                )
            )
        ordinary_templates = {
            item
            for item in str(authority_row["template_ids"]).split(";")
            if item
        }
        if template_id not in ordinary_templates:
            _fail(
                "{} canonical template {!r} is not declared by the matching ordinary E3 cell".format(
                    location, template_id
                )
            )
        canonical_templates.add(template_id)
        if receipt["measurement_protocol"] != "not_applicable/correctness_only":
            _fail(
                "{} has measurement_protocol={!r}; expected 'not_applicable/correctness_only'".format(
                    location, receipt["measurement_protocol"]
                )
            )
        if receipt["status"] != "pass":
            _fail(
                "{} has status={!r}; expected 'pass'".format(
                    location, receipt["status"]
                )
            )
        row_count = _as_int(receipt["row_count"], str(location) + " row_count")
        reference_count = _as_int(
            receipt["reference_row_count"],
            str(location) + " reference_row_count",
        )
        if row_count < 0 or reference_count < 0:
            _fail("{} has a negative canonical row count".format(location))
        if row_count != reference_count:
            _fail(
                "{} canonical row count differs from reference ({} != {})".format(
                    location, row_count, reference_count
                )
            )

        result_digest = _sha256_digest(
            receipt["result_digest"], "result_digest", location
        )
        reference_digest = _sha256_digest(
            receipt["reference_digest"], "reference_digest", location
        )
        if result_digest != reference_digest:
            _fail("{} canonical result digest differs from reference".format(location))

        actual_only = _as_int(
            receipt["actual_only_rows"], str(location) + " actual_only_rows"
        )
        reference_only = _as_int(
            receipt["reference_only_rows"],
            str(location) + " reference_only_rows",
        )
        if actual_only != 0 or reference_only != 0:
            _fail(
                "{} has nonzero canonical bag difference (actual_only={}, reference_only={})".format(
                    location, actual_only, reference_only
                )
            )

        ordered_match = _csv_bool(
            receipt["ordered_sequence_match"],
            "ordered_sequence_match",
            location,
        )
        ordered_matches += int(ordered_match)
        manifest_ids.add(receipt["manifest_id"])
        manifest_hash = _sha256_digest(
            receipt["manifest_sha256"], "manifest_sha256", location
        )
        canonical_manifest_hashes.add(manifest_hash)
        dataset_scales.add(receipt["dataset_scale"])
        seeds.add(receipt["seed"])
        commit = _git_commit(receipt["git_commit"], "git_commit", location)
        git_commits.add(commit)
        authority_row.update(
            {
                "canonical_content_receipt_status": "pass",
                "canonical_content_receipt_source": _output_reference(
                    repo_root, source
                ),
                "canonical_content_source_commit": commit,
                "canonical_content_manifest_sha256": manifest_hash,
                "canonical_content_measurement_protocol": receipt[
                    "measurement_protocol"
                ],
                "canonical_content_template_id": template_id,
                "canonical_content_row_count": row_count,
                "canonical_content_digest": result_digest,
                "canonical_content_actual_only_rows": actual_only,
                "canonical_content_reference_only_rows": reference_only,
                "canonical_content_ordered_sequence_match": str(
                    ordered_match
                ).lower(),
            }
        )

    if len(git_commits) != 1:
        _fail(
            "{} canonical receipts identify {} Git commits; expected exactly one".format(
                source, len(git_commits)
            )
        )

    if len(canonical_manifest_hashes) != 1:
        _fail(
            "{} canonical receipts identify {} manifest hashes; expected exactly one".format(
                source, len(canonical_manifest_hashes)
            )
        )
    canonical_manifest_hash = next(iter(canonical_manifest_hashes))
    if canonical_manifest_hash != ordinary_manifest_hash:
        _fail(
            "{} canonical manifest_sha256 does not match ordinary E3 manifest hash".format(
                source
            )
        )

    return {
        "experiment": "E3",
        "evidence_kind": "canonical_content_receipts",
        "check_kind": "independent_full_row_jsonb_multiset_equality",
        "scope": (
            "One independent canonical full-row multiset receipt per E3 logical "
            "cell; ordered sequence is retained only as a diagnostic."
        ),
        "source_file": _output_reference(repo_root, source),
        "source_sha256": _sha256_file(source),
        "canonical_content_source_commit": next(iter(git_commits)),
        "manifest_sha256": canonical_manifest_hash,
        "identity_fields": list(E3_CANONICAL_IDENTITY_FIELDS),
        "source_commit": next(iter(git_commits)),
        "snapshot": {
            "git_commits": sorted(git_commits),
            "manifest_ids": sorted(manifest_ids),
            "manifest_hashes": [canonical_manifest_hash],
            "dataset_scales": sorted(dataset_scales),
            "seeds": sorted(seeds),
        },
        "representation_alignment": {
            "canonical_template_ids": sorted(canonical_templates),
            "ordinary_field": "template_ids",
            "canonical_fields": [
                "template_id",
                "admission_first_selected_template",
            ],
        },
        "counts": {
            "cells_expected": 33,
            "cells_passed": 33,
            "receipts": 33,
            "ordered_sequence_matches": ordered_matches,
        },
        "checks": {
            "exactly_one_receipt_per_cell": True,
            "identities_match_ordinary_e3_cell_universe": True,
            "all_status_pass": True,
            "all_measurement_protocols_correctness_only": True,
            "single_canonical_manifest_sha256": True,
            "canonical_manifest_matches_ordinary_e3": True,
            "all_canonical_template_fields_nonempty": True,
            "all_canonical_template_fields_equal": True,
            "all_canonical_templates_match_ordinary": True,
            "all_actual_reference_counts_equal": True,
            "all_actual_reference_digests_equal": True,
            "all_canonical_bag_differences_zero": True,
            "ordered_sequence_match_is_required": False,
        },
        "status": "pass",
    }


def _validate_raw_record(repo_root: Path, row: Mapping[str, str]) -> Path:
    raw_path = Path(row["raw_path"])
    source = raw_path if raw_path.is_absolute() else repo_root / raw_path
    raw = _read_json(source)

    try:
        raw_mode = normalize_mode_id(str(_nested(raw, ("mode",), source)))
    except ValueError as exc:
        _fail("{} has invalid mode: {}".format(source, exc))
    _expect(raw_mode, ADMISSION_FIRST_MODE, "mode", source)

    scalar_checks = (
        (("run_id",), row["run_id"], "run_id"),
        (("experiment",), row["experiment"], "experiment"),
        (("status",), "pass", "status"),
        (("manifest_id",), row["manifest_id"], "manifest_id"),
        (("manifest_hash",), row["manifest_hash"], "manifest_hash"),
        (("implementation", "git_commit"), row["git_commit"], "implementation.git_commit"),
        (("measurement", "phase"), row["measurement_phase"], "measurement.phase"),
        (
            ("measurement", "iteration"),
            _as_int(row["measurement_iteration"], "measurement_iteration"),
            "measurement.iteration",
        ),
        (
            ("measurement", "warmup_repetitions"),
            _as_int(row["measurement_warmup_repetitions"], "measurement_warmup_repetitions"),
            "measurement.warmup_repetitions",
        ),
        (
            ("measurement", "measured_repetitions"),
            _as_int(row["measurement_measured_repetitions"], "measurement_measured_repetitions"),
            "measurement.measured_repetitions",
        ),
        (("query", "query_id"), row["query_id"], "query.query_id"),
        (("policy", "policy_id"), row["policy_id"], "policy.policy_id"),
        (("context", "context_id"), row["context_id"], "context.context_id"),
        (("template", "template_id"), row["template_id"], "template.template_id"),
        (("oracle_check", "status"), "match", "oracle_check.status"),
        (("runtime_audit", "status"), "pass", "runtime_audit.status"),
        (("runtime_audit", "unauthorized_observations"), 0, "runtime_audit.unauthorized_observations"),
        (("result", "result_hash"), row["result_hash"], "result.result_hash"),
    )
    for path, expected, label in scalar_checks:
        _expect(_nested(raw, path, source), expected, label, source)

    for raw_key, csv_key in (("name", "dataset_name"), ("scale", "dataset_scale"), ("seed", "dataset_seed")):
        actual = _nested(raw, ("dataset", raw_key), source)
        _expect(str(actual), str(row[csv_key]), "dataset.{}".format(raw_key), source)
    return source


def _validate_source_summary(
    path: Path,
    spec: FamilySpec,
    selected_rows: Sequence[Mapping[str, str]],
) -> Mapping[str, Any]:
    payload = _read_json(path)
    _expect(payload.get("experiment"), spec.experiment, "experiment", path)
    protocol = payload.get("measurement_protocol")
    if not isinstance(protocol, Mapping):
        _fail("{} is missing measurement_protocol".format(path))
    _expect(protocol.get("status"), "ok", "measurement_protocol.status", path)
    _expect(
        _as_int(protocol.get("required_warmup_repetitions"), "required_warmup_repetitions"),
        spec.warmup_repetitions,
        "measurement_protocol.required_warmup_repetitions",
        path,
    )
    _expect(
        _as_int(protocol.get("required_measured_repetitions"), "required_measured_repetitions"),
        spec.measured_repetitions,
        "measurement_protocol.required_measured_repetitions",
        path,
    )
    mode_counts = payload.get("mode_counts")
    if not isinstance(mode_counts, Mapping):
        _fail("{} is missing mode_counts".format(path))
    canonical_mode_counts: Dict[str, Any] = {}
    for raw_mode, count in mode_counts.items():
        try:
            mode = normalize_mode_id(str(raw_mode))
        except ValueError as exc:
            _fail("{} has invalid mode_counts key {!r}: {}".format(path, raw_mode, exc))
        if mode in canonical_mode_counts:
            _fail(
                "{} aliases more than one mode_counts key to {}".format(
                    path, mode
                )
            )
        canonical_mode_counts[mode] = count
    _expect(
        _as_int(
            canonical_mode_counts.get(ADMISSION_FIRST_MODE),
            "mode_counts.admission-first",
        ),
        len(selected_rows),
        "mode_counts.admission-first",
        path,
    )

    row_manifest_hashes = sorted({row["manifest_hash"] for row in selected_rows})
    row_git_commits = sorted({row["git_commit"] for row in selected_rows})
    summary_manifest_hashes = sorted(str(item) for item in payload.get("manifest_hashes", []))
    summary_git_commits = sorted(str(item) for item in payload.get("git_commits", []))
    _expect(summary_manifest_hashes, row_manifest_hashes, "manifest_hashes", path)
    _expect(summary_git_commits, row_git_commits, "git_commits", path)
    return payload


def _validate_family(
    repo_root: Path,
    summary_root: Path,
    spec: FamilySpec,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    family_dir = summary_root / spec.family
    runs_path = family_dir / "runs.csv"
    cells_path = family_dir / "cell_stats.csv"
    source_summary_path = family_dir / "summary.json"
    all_runs, run_fields = _read_csv(runs_path, RUN_REQUIRED_COLUMNS)
    all_cells, cell_fields = _read_csv(cells_path, CELL_REQUIRED_COLUMNS)
    selected_runs = [
        row
        for row in all_runs
        if normalize_mode_id(str(row["mode"])) == ADMISSION_FIRST_MODE
    ]
    selected_cells = [
        row
        for row in all_cells
        if normalize_mode_id(str(row["mode"])) == ADMISSION_FIRST_MODE
    ]
    if len(selected_cells) != spec.expected_cells:
        _fail(
            "{} has {} AdmissionFirst cases; expected {}".format(
                cells_path, len(selected_cells), spec.expected_cells
            )
        )
    expected_records = spec.expected_cells * (
        spec.warmup_repetitions + spec.measured_repetitions
    )
    if len(selected_runs) != expected_records:
        _fail(
            "{} has {} AdmissionFirst run records; expected {}".format(
                runs_path, len(selected_runs), expected_records
            )
        )

    _validate_source_summary(source_summary_path, spec, selected_runs)
    parameter_columns = _parameter_columns(run_fields, cell_fields)
    run_groups: Dict[Tuple[str, ...], List[Dict[str, str]]] = {}
    for row_number, row in enumerate(selected_runs, start=2):
        location = "{}:{}".format(runs_path, row_number)
        if row["experiment"] != spec.experiment:
            _fail("{} has experiment={!r}".format(location, row["experiment"]))
        if row["run_kind"] != "normal_mode":
            _fail("{} has run_kind={!r}; expected 'normal_mode'".format(location, row["run_kind"]))
        expected_values = {
            "status": "pass",
            "oracle_status": "match",
            "runtime_audit_status": "pass",
        }
        for field, expected in expected_values.items():
            if row[field] != expected:
                _fail("{} has {}={!r}; expected {!r}".format(location, field, row[field], expected))
        if _as_int(row["unauthorized_observations"], location + " unauthorized_observations") != 0:
            _fail("{} has unauthorized observations".format(location))
        if not row["result_hash"].strip():
            _fail("{} has an empty result_hash".format(location))
        if _as_int(row["measurement_warmup_repetitions"], location + " warmups") != spec.warmup_repetitions:
            _fail("{} has the wrong declared warmup count".format(location))
        if _as_int(row["measurement_measured_repetitions"], location + " measured") != spec.measured_repetitions:
            _fail("{} has the wrong declared measured count".format(location))
        if row["measurement_phase"] not in {"warmup", "measured"}:
            _fail("{} has unknown measurement_phase={!r}".format(location, row["measurement_phase"]))
        run_groups.setdefault(_cell_key(row, parameter_columns), []).append(row)

    if len(run_groups) != spec.expected_cells:
        _fail(
            "{} AdmissionFirst rows form {} cells; expected {}".format(
                runs_path, len(run_groups), spec.expected_cells
            )
        )

    cell_by_key: Dict[Tuple[str, ...], Dict[str, str]] = {}
    for row_number, row in enumerate(selected_cells, start=2):
        key = _cell_key(row, parameter_columns)
        if key in cell_by_key:
            _fail("{}:{} duplicates a AdmissionFirst cell".format(cells_path, row_number))
        cell_by_key[key] = row
    if set(cell_by_key) != set(run_groups):
        missing = len(set(run_groups) - set(cell_by_key))
        extra = len(set(cell_by_key) - set(run_groups))
        _fail("{} and {} disagree on cells (missing={}, extra={})".format(runs_path, cells_path, missing, extra))

    seen_raw_paths = set()
    seen_run_ids = set()
    output_rows: List[Dict[str, Any]] = []
    for key in sorted(run_groups):
        rows = run_groups[key]
        representative = rows[0]
        stats = cell_by_key[key]
        phase_rows = {
            phase: [row for row in rows if row["measurement_phase"] == phase]
            for phase in ("warmup", "measured")
        }
        for phase, expected_count in (
            ("warmup", spec.warmup_repetitions),
            ("measured", spec.measured_repetitions),
        ):
            observed_iterations = sorted(
                _as_int(row["measurement_iteration"], "measurement_iteration")
                for row in phase_rows[phase]
            )
            expected_iterations = list(range(1, expected_count + 1))
            if observed_iterations != expected_iterations:
                _fail(
                    "{} {} iterations are {}; expected {}".format(
                        _cell_id(spec.family, representative, parameter_columns),
                        phase,
                        observed_iterations,
                        expected_iterations,
                    )
                )

        for row in rows:
            if row["raw_path"] in seen_raw_paths:
                _fail("duplicate raw_path in correctness authority: {}".format(row["raw_path"]))
            if row["run_id"] in seen_run_ids:
                _fail("duplicate run_id in correctness authority: {}".format(row["run_id"]))
            seen_raw_paths.add(row["raw_path"])
            seen_run_ids.add(row["run_id"])
            _validate_raw_record(repo_root, row)

        total = spec.warmup_repetitions + spec.measured_repetitions
        stats_source = cells_path
        numeric_expectations = {
            "sample_count": spec.measured_repetitions,
            "warmup_count": spec.warmup_repetitions,
            "total_record_count": total,
            "required_warmup_repetitions": spec.warmup_repetitions,
            "required_measured_repetitions": spec.measured_repetitions,
        }
        for field, expected in numeric_expectations.items():
            _expect(_as_int(stats[field], field), expected, field, stats_source)
        _expect(stats["protocol_status"], "ok", "protocol_status", stats_source)
        try:
            status_counts = json.loads(stats["status_counts"])
        except json.JSONDecodeError as exc:
            raise SigmodPreviewError("{} has invalid status_counts JSON".format(stats_source)) from exc
        _expect(status_counts, {"pass": total}, "status_counts", stats_source)

        manifests = sorted({row["manifest_hash"] for row in rows})
        stats_manifests = sorted(item for item in stats["manifest_hashes"].split(";") if item)
        _expect(stats_manifests, manifests, "manifest_hashes", stats_source)
        templates = sorted({row["template_id"] for row in rows})
        stats_templates = sorted(_json_list(stats["observed_template_ids"], "observed_template_ids", stats_source))
        _expect(stats_templates, templates, "observed_template_ids", stats_source)

        output_rows.append(
            {
                "family": spec.family,
                "check_kind": spec.check_kind,
                "scope": spec.scope,
                "cell_id": _cell_id(spec.family, representative, parameter_columns),
                "experiment": representative["experiment"],
                "dataset_name": representative["dataset_name"],
                "dataset_scale": representative["dataset_scale"],
                "dataset_seed": representative["dataset_seed"],
                "query_id": representative["query_id"],
                "policy_id": representative["policy_id"],
                "context_id": representative["context_id"],
                "cell_parameters_json": json.dumps(
                    _cell_parameters(representative, parameter_columns),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "template_ids": ";".join(templates),
                "manifest_ids": ";".join(sorted({row["manifest_id"] for row in rows})),
                "manifest_hashes": ";".join(manifests),
                "git_commits": ";".join(sorted({row["git_commit"] for row in rows})),
                "warmup_records": spec.warmup_repetitions,
                "measured_records": spec.measured_repetitions,
                "total_records": total,
                "status_pass_records": sum(row["status"] == "pass" for row in rows),
                "oracle_match_records": sum(row["oracle_status"] == "match" for row in rows),
                "runtime_audit_pass_records": sum(
                    row["runtime_audit_status"] == "pass" for row in rows
                ),
                "unauthorized_observations": sum(
                    _as_int(row["unauthorized_observations"], "unauthorized_observations")
                    for row in rows
                ),
                "nonempty_result_hash_records": sum(bool(row["result_hash"].strip()) for row in rows),
                "raw_records_checked": len(rows),
                "protocol_status": stats["protocol_status"],
                "correctness_status": "pass",
            }
        )

    family_manifest_ids = sorted({row["manifest_id"] for row in selected_runs})
    family_manifest_hashes = sorted({row["manifest_hash"] for row in selected_runs})
    family_git_commits = sorted({row["git_commit"] for row in selected_runs})
    for label, values in (
        ("manifest_ids", family_manifest_ids),
        ("manifest_hashes", family_manifest_hashes),
        ("git_commits", family_git_commits),
    ):
        if len(values) != 1:
            _fail(
                "{} has {} {}; expected exactly one".format(
                    spec.family, len(values), label
                )
            )
    family_summary: Dict[str, Any] = {
        "family": spec.family,
        "experiment": spec.experiment,
        "evidence_kind": "ordinary_runner",
        "check_kind": spec.check_kind,
        "scope": spec.scope,
        "source_files": {
            "raw_directory": "results/raw/{}".format(spec.family),
            "runs_csv": "results/summarized/{}/runs.csv".format(spec.family),
            "cell_stats_csv": "results/summarized/{}/cell_stats.csv".format(spec.family),
            "summary_json": "results/summarized/{}/summary.json".format(spec.family),
        },
        "snapshot": {
            "manifest_ids": family_manifest_ids,
            "manifest_hashes": family_manifest_hashes,
            "git_commits": family_git_commits,
        },
        "counts": {
            "cells": len(output_rows),
            "warmup_records": spec.expected_cells * spec.warmup_repetitions,
            "measured_records": spec.expected_cells * spec.measured_repetitions,
            "total_records": len(selected_runs),
            "raw_records_checked": len(selected_runs),
        },
        "checks": {
            "all_status_pass": True,
            "all_oracle_match": True,
            "all_runner_recorded_runtime_status_pass": True,
            "runner_recorded_unauthorized_field_sum_zero": True,
            "runner_recorded_unauthorized_field_sum": 0,
            "all_result_hashes_nonempty": True,
            "cell_stats_protocol_status": "ok",
            "runtime_audit_fields_kind": "runner_recorded_bookkeeping",
        },
        "status": "pass",
    }
    return output_rows, family_summary


def generate_sigmod_preview(
    repo_root: Path = Path("."),
    output_dir: Optional[Path] = None,
    family_specs: Sequence[FamilySpec] = DEFAULT_FAMILIES,
    e3_canonical_receipts: Optional[Path] = None,
) -> PreviewResult:
    """Validate existing evidence and write the paper correctness authority.

    The output is deterministic: it contains no generation timestamp and
    claims a single combined execution snapshot only when every included
    family records the same execution commit.  E3 canonical content receipts
    are loaded only from the explicit input (or its fresh-directory default);
    stale preview directories are never searched.
    """

    root = Path(repo_root)
    summary_root = root / "results" / "summarized"
    if output_dir is None:
        destination = root / DEFAULT_OUTPUT_DIR
    else:
        destination = output_dir
    if output_dir is not None and not destination.is_absolute():
        destination = root / destination

    rows: List[Dict[str, Any]] = []
    families: List[Dict[str, Any]] = []
    for spec in family_specs:
        family_rows, family_summary = _validate_family(root, summary_root, spec)
        rows.extend(family_rows)
        families.append(family_summary)

    canonical_receipt_path = (
        DEFAULT_E3_CANONICAL_RECEIPTS
        if e3_canonical_receipts is None
        else Path(e3_canonical_receipts)
    )
    e3_content_authority = _validate_e3_canonical_receipts(
        root, canonical_receipt_path, rows
    )
    for family in families:
        if family["experiment"] == "E3":
            family["record_evidence_role"] = "ordinary_count_provenance"
            family["canonical_content_authority"] = e3_content_authority
    rows.sort(key=lambda row: (str(row["family"]), str(row["cell_id"])))

    expected_cells = sum(spec.expected_cells for spec in family_specs)
    if len(rows) != expected_cells:
        _fail("combined correctness authority has {} cells; expected {}".format(len(rows), expected_cells))
    ordinary_distinct_commits = sorted(
        {
            commit
            for family in families
            for commit in family["snapshot"]["git_commits"]
        }
    )
    canonical_distinct_commits = list(
        e3_content_authority["snapshot"]["git_commits"]
    )
    distinct_commits = sorted(
        set(ordinary_distinct_commits) | set(canonical_distinct_commits)
    )
    total_warmups = sum(int(row["warmup_records"]) for row in rows)
    total_measured = sum(int(row["measured_records"]) for row in rows)
    total_records = sum(int(row["total_records"]) for row in rows)
    e3_ordinary_records = sum(
        int(row["total_records"]) for row in rows if row["experiment"] == "E3"
    )
    single_combined_snapshot = len(distinct_commits) == 1
    snapshot_policy: Dict[str, Any] = {
        "single_combined_snapshot_claimed": single_combined_snapshot,
        "distinct_git_commits": distinct_commits,
        "ordinary_family_snapshots": {
            "distinct_git_commits": ordinary_distinct_commits,
        },
        "e3_canonical_content_snapshot": e3_content_authority["snapshot"],
        "note": (
            "All family run records and E3 canonical content receipts identify the same execution commit."
            if single_combined_snapshot
            else "Family run records and E3 canonical content receipts retain their own recorded manifests and Git commits; no single combined execution snapshot is asserted."
        ),
    }
    if single_combined_snapshot:
        snapshot_policy["execution_commit"] = distinct_commits[0]

    correctness_scopes = [
        {
            "family": spec.family,
            "experiment": spec.experiment,
            "check_kind": spec.check_kind,
            "scope": spec.scope,
        }
        for spec in family_specs
    ]

    cells_csv = destination / CORRECTNESS_CELLS_FILENAME
    summary_json = destination / CORRECTNESS_SUMMARY_FILENAME
    summary: Dict[str, Any] = {
        "schema_version": "caprls-sigmod-correctness-v3",
        "authority": "paper_correctness",
        "evidence_kind": "ordinary_runner_plus_e3_canonical_content_receipts",
        "scope": (
            "Family-specific ordinary-runner count evidence for AdmissionFirst "
            "E2, E3, and E10 cells, plus one canonical full-row multiset "
            "receipt for each E3 cell"
        ),
        "status": "pass",
        "correctness_claim": (
            "{}/{} final AdmissionFirst cases passed their gates; {}/{} retained "
            "run records passed family-specific count checks; {}/{} "
            "additional E3 canonical row-multiset receipts passed"
        ).format(
            len(rows),
            expected_cells,
            total_records,
            total_records,
            e3_content_authority["counts"]["cells_passed"],
            e3_content_authority["counts"]["cells_expected"],
        ),
        "correctness_scopes": correctness_scopes,
        "canonical_content_authorities": [e3_content_authority],
        "canonical_content_source_commit": e3_content_authority[
            "canonical_content_source_commit"
        ],
        "canonical_content_manifest_sha256": e3_content_authority[
            "manifest_sha256"
        ],
        "evidence_semantics": {
            "headline_basis": (
                "The run records provide family-specific count provenance. "
                "A separate 33-receipt E3 authority provides canonical full-row "
                "multiset equality once per logical E3 cell."
            ),
            "ordinary_runner_count_provenance": {
                "total_records": total_records,
                "e3_records": e3_ordinary_records,
                "interpretation": (
                    "The 495 retained E3 run records establish recorded "
                    "output-row-count equality only; they are not presented as "
                    "495 full-content equality receipts."
                ),
            },
            "e3_canonical_content_receipts": {
                "cells_expected": e3_content_authority["counts"]["cells_expected"],
                "cells_passed": e3_content_authority["counts"]["cells_passed"],
                "source_file": e3_content_authority["source_file"],
                "interpretation": (
                    "Exactly one independent canonical full-row multiset "
                    "equality receipt is required for each of the 33 E3 cells."
                ),
            },
            "runner_recorded_bookkeeping": {
                "fields": [
                    "runtime_audit_status",
                    "runtime_audit_pass_records",
                    "unauthorized_observations",
                ],
                "interpretation": "These values are retained and cross-checked as runner-recorded bookkeeping; this package does not present them as an independent dynamic proof.",
            },
            "e7_separate_witness": {
                "experiment": "E7",
                "included_in_authority": False,
                "interpretation": "E7 is a separate bounded live observation witness; it is not part of this 52-case run-based correctness authority.",
            },
        },
        "snapshot_policy": snapshot_policy,
        "families": families,
        "totals": {
            "family_count": len(families),
            "cells_expected": expected_cells,
            "cells_passed": len(rows),
            "final_cell_gates_expected": expected_cells,
            "final_cell_gates_passed": len(rows),
            "warmup_records": total_warmups,
            "measured_records": total_measured,
            "total_records": total_records,
            "ordinary_count_provenance_records": total_records,
            "ordinary_records_expected": total_records,
            "ordinary_records_passed": total_records,
            "e3_ordinary_count_provenance_records": e3_ordinary_records,
            "e3_canonical_content_receipts": e3_content_authority["counts"][
                "receipts"
            ],
            "e3_canonical_content_cells_expected": e3_content_authority["counts"][
                "cells_expected"
            ],
            "e3_canonical_content_cells_passed": e3_content_authority["counts"][
                "cells_passed"
            ],
            "raw_records_checked": total_records,
            "status_pass_records": sum(int(row["status_pass_records"]) for row in rows),
            "oracle_match_records": sum(int(row["oracle_match_records"]) for row in rows),
            "runtime_audit_pass_records": sum(
                int(row["runtime_audit_pass_records"]) for row in rows
            ),
            "unauthorized_observations": sum(
                int(row["unauthorized_observations"]) for row in rows
            ),
            "nonempty_result_hash_records": sum(
                int(row["nonempty_result_hash_records"]) for row in rows
            ),
        },
        "checks": {
            "all_cells_present": len(rows) == expected_cells,
            "all_status_pass": True,
            "all_oracle_match": True,
            "all_runner_recorded_runtime_status_pass": True,
            "runner_recorded_unauthorized_field_sum_zero": True,
            "all_result_hashes_nonempty": True,
            "all_raw_records_cross_checked": True,
            "e3_canonical_content_receipts_complete": True,
            "e3_canonical_manifest_matches_ordinary_e3": True,
            "e3_canonical_measurement_protocol_correctness_only": True,
            "e3_canonical_templates_match_ordinary": True,
            "e3_canonical_actual_reference_counts_equal": True,
            "e3_canonical_actual_reference_digests_equal": True,
            "e3_canonical_bag_differences_zero": True,
            "runtime_audit_fields_kind": "runner_recorded_bookkeeping",
        },
        "outputs": {
            "cells_csv": _output_reference(root, cells_csv),
            "summary_json": _output_reference(root, summary_json),
        },
    }

    destination.mkdir(parents=True, exist_ok=True)
    with cells_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    summary_json.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return PreviewResult(cells_csv=cells_csv, summary_json=summary_json, summary=summary)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the ordinary-runner SIGMOD paper correctness authority"
    )
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="output directory (default: results/summarized/SIGMOD_CURRENT)",
    )
    parser.add_argument(
        "--e3-canonical-receipts",
        type=Path,
        default=None,
        help=(
            "E3 canonical receipt CSV (default: "
            "results/raw/E3_CANONICAL_CORRECTNESS_V1/summary.csv)"
        ),
    )
    args = parser.parse_args(argv)
    try:
        result = generate_sigmod_preview(
            args.root,
            args.output_dir,
            e3_canonical_receipts=args.e3_canonical_receipts,
        )
    except SigmodPreviewError as exc:
        parser.exit(2, "sigmod-results: error: {}\n".format(exc))
    print(
        "{}; wrote {} and {}".format(
            result.summary["correctness_claim"], result.cells_csv, result.summary_json
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
