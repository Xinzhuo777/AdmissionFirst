"""Shared utilities for selection-cost experiments."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import hashlib
import inspect
import json
import math
import os
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from caprls_core import content_verify as cv

# --------------------------------------------------------------------------
# Campaign identity
# --------------------------------------------------------------------------

CAMPAIGN_B = "SELECTION_COST_V1"
CAMPAIGN_C = "STABILITY_WITNESS_V1"

RECEIPT_SCHEMA_B = "caprls-selection-cost-receipt-v1"
SUMMARY_SCHEMA_B = "caprls-selection-cost-summary-v1"
ROUND_SCHEMA_C = "caprls-stability-witness-round-v1"
RECEIPT_SCHEMA_C = "caprls-stability-witness-receipt-v1"
SUMMARY_SCHEMA_C = "caprls-stability-witness-summary-v1"

DESIGN_MEMO = (
    "reference/"
    "selection_cost_protocol.md"
)
SPEC_PATH = "specs/selection_cost_cells.yaml"
PREDECLARATION_NAME = "predeclared_selection_cost.yaml"

#: New modules only.  ``caprls_core/cli.py`` is a measurement-path file and is
#: NOT touched; the campaigns ship their own standalone entry point, exactly as
#: R3 shipped ``content_cli.py``.
HARNESS_MODULES = (
    "selection_cost_common.py",
    "selection_cost_e3.py",
    "selection_cost_e10.py",
    "selection_cost_analyze.py",
    "selection_cost_predeclare.py",
    "selection_cost_cli.py",
    "stability_witness_e3.py",
)

SOURCE_GLOBS = (
    "caprls_core/**/*.py",
    "planner/**/*.py",
    "sql/**/*.sql",
    "manifests/**/*.yaml",
    "specs/selection_cost_cells.yaml",
    "specs/selection_difference_classification.yaml",
)

#: Gate ruling (a): the four frozen functions rebound in memory during a run.
#: ``e3_main._plan_e3_admission_first`` is deliberately ABSENT - it is bracketed
#: from outside and never wrapped, which is strictly safer.
REBOUND_FUNCTIONS: Tuple[Dict[str, str], ...] = (
    {
        "module": "caprls_core.e3_main",
        "function": "_verify_e3_static",
        "purpose": "observe per-candidate prospective cost and EXPLAIN wall time",
        "campaigns": "B(E3), C",
    },
    {
        "module": "caprls_core.e10_study",
        "function": "_e10_planning_expectation",
        "purpose": "selection-wall START anchor",
        "campaigns": "B(E10)",
    },
    {
        "module": "caprls_core.e10_study",
        "function": "_planner_invocation_for_case",
        "purpose": "selection-wall STOP anchor",
        "campaigns": "B(E10)",
    },
    {
        "module": "caprls_core.e10_study",
        "function": "_prospective_pg_cost",
        "purpose": "observe per-candidate EXPLAIN wall time",
        "campaigns": "B(E10)",
    },
)
REBIND_RESTORE_GUARANTEE = "restored_in_finally_unconditionally"

#: C5: the reused frozen latency-measurement functions whose source is digested
#: into every campaign identity block.  "Reused verbatim" must be evidenced.
LATENCY_FUNCTIONS: Tuple[Tuple[str, str], ...] = (
    ("caprls_core.e3_main", "_measure_e3_query"),
    ("caprls_core.e8b_study", "_run_validated_query"),
    ("caprls_core.e8b_study", "QueryTiming"),
    ("caprls_core.e10_study", "_measure_query"),
    ("caprls_core.e10_study", "_measure_validated_query"),
    ("caprls_core.e10_study", "_prepare_postgres_measurements"),
)

#: Frozen measurement-path files that must be byte-identical to HEAD.
FROZEN_PATHS = (
    "caprls_core/e3_main.py",
    "caprls_core/e10_study.py",
    "caprls_core/e3_sigmod_preview.py",
    "caprls_core/e8b_study.py",
    "caprls_core/postgres_runner.py",
    "caprls_core/cli.py",
    "caprls_core/reporting.py",
    "caprls_core/e3_scale_check.py",
)

# --------------------------------------------------------------------------
# Frozen aggregation rules (reused, never re-invented)
# --------------------------------------------------------------------------

#: ``caprls_core/e3_scale_check.py:33`` - the frozen symmetric 1% tie band.
TIE_LOWER_BOUND, TIE_FACTOR = 0.99, 1.01
#: Pre-fixed amortization grid.  No other k is computed or reported.
K_GRID: Tuple[int, ...] = (1, 2, 5, 10, 100)
#: Protocol repetition counts (memo section 1.5 / 2.3).
E3_SELECTION_WARMUP, E3_SELECTION_MEASURED = 1, 5
E10_SELECTION_WARMUP, E10_SELECTION_MEASURED = 5, 10
LATENCY_WARMUP, LATENCY_MEASURED = 5, 10
C_ROUNDS = 10

E3_MANIFEST = "manifests/experiments/e3_standard_sf1_rawpg.yaml"
E10_MANIFEST = "manifests/experiments/e10_case_study.yaml"
CLASSIFICATION_SPEC = "specs/selection_difference_classification.yaml"

#: C4: the measurand-asymmetry label.  Structurally inseparable from any pooled
#: figure - see :func:`pooled_aggregate`, which refuses to build a pooled dict
#: without it, and :func:`assert_pooled_labels_present`.
POOLED_MEASURAND_SCOPE_MISMATCH = (
    "e3_wall_excludes_planning_inputs; e10_wall_includes_them"
)
POOLED_AGGREGATION_SCOPE = "pooled_across_two_dissimilar_families"
#: C3: the only pairing a pooled figure may be computed on.
POOLED_COMMENSURABLE_PAIRING = (
    "e3=selection_wall_plus_inputs_ms; e10=selection_wall_ms"
)


class SelectionCostError(RuntimeError):
    """Fail-closed error for the selection-cost campaigns."""


class SystematicStop(SelectionCostError):
    """A stop rule fired.  Carries the evidence already collected.

    R3's F8 lesson, third occurrence: a stop path that discards the diagnostic
    it had already collected leaves a sealed package that cannot tell an auditor
    why its cells failed.  Everything this exception carries has **already been
    written to disk** by the time it is raised - the payload exists so the
    summary can count it, not so it can be rescued.
    """

    def __init__(
        self,
        message: str,
        *,
        receipts: Optional[Sequence[Mapping[str, Any]]] = None,
        failures: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.receipts: List[Mapping[str, Any]] = list(receipts or [])
        self.failures: List[Mapping[str, Any]] = list(failures or [])


# --------------------------------------------------------------------------
# Digests and identity
# --------------------------------------------------------------------------


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return cv._sha256_file(path)


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_canonical(payload: Any) -> str:
    return sha256_text(canonical_json(payload))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def function_digest(module_name: str, attr: str) -> Dict[str, Any]:
    """Digest one frozen function/class body (C5).

    Records the source digest, the defining file and the first line, so a
    later audit can re-derive it without trusting this record.
    """

    import importlib

    module = importlib.import_module(module_name)
    obj = getattr(module, attr, None)
    if obj is None:
        raise SelectionCostError(f"missing frozen symbol {module_name}.{attr}")
    try:
        source = inspect.getsource(obj)
        _, first_line = inspect.getsourcelines(obj)
    except (OSError, TypeError) as exc:  # pragma: no cover - defensive
        raise SelectionCostError(
            f"cannot read source of {module_name}.{attr}: {exc}"
        ) from exc
    return {
        "symbol": f"{module_name}.{attr}",
        "file": os.path.relpath(inspect.getfile(obj), start=repo_root()),
        "first_line": int(first_line),
        "line_count": len(source.splitlines()),
        "source_digest": sha256_text(source),
    }


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def git_head_state(root: Path) -> Dict[str, Any]:
    return cv.git_identity(root)


def frozen_files_unchanged(root: Path) -> Dict[str, Any]:
    """Byte-intactness proof for every frozen measurement-path file."""

    dirty: List[str] = []
    for rel in FROZEN_PATHS:
        proc = subprocess.run(
            ["git", "status", "--porcelain", "--", rel],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.stdout.strip():
            dirty.append(proc.stdout.strip())
    return {
        "checked": list(FROZEN_PATHS),
        "modified": dirty,
        "all_byte_identical_to_head": not dirty,
    }


def identity_block(
    root: Path,
    *,
    campaign: str,
    spec_path: Optional[Path] = None,
    predeclaration_path: Optional[Path] = None,
    manifest_paths: Sequence[Path] = (),
) -> Dict[str, Any]:
    """The campaign identity recorded in every receipt and summary."""

    block: Dict[str, Any] = {
        "campaign": campaign,
        "source": _source_identity(root),
        "harness": _harness_identity(root),
        "git": git_head_state(root),
        "frozen_measurement_files": frozen_files_unchanged(root),
        # C5 - reused latency-measurement function digests.
        "reused_latency_function_digests": [
            function_digest(mod, attr) for mod, attr in LATENCY_FUNCTIONS
        ],
        # Gate ruling (a) - runtime rebinding, named explicitly.
        "runtime_rebound_frozen_functions": {
            "note": (
                "additive-only refers to disk state, not to runtime binding; "
                "each wrapper delegates unchanged and is restored in finally"
            ),
            "restore_guarantee": REBIND_RESTORE_GUARANTEE,
            "externally_bracketed_never_wrapped": (
                "caprls_core.e3_main._plan_e3_admission_first"
            ),
            "functions": [dict(entry) for entry in REBOUND_FUNCTIONS],
        },
        "design_memo": DESIGN_MEMO,
        "design_memo_digest": sha256_file(root / DESIGN_MEMO),
        "python_version": sys.version.split()[0],
    }
    if spec_path is not None:
        block["spec_path"] = os.path.relpath(spec_path, start=root)
        block["spec_digest"] = sha256_file(spec_path)
    if predeclaration_path is not None:
        block["predeclaration_path"] = os.path.relpath(predeclaration_path, start=root)
        block["predeclaration_digest"] = sha256_file(predeclaration_path)
    block["manifests"] = [
        {
            "path": os.path.relpath(path, start=root),
            "digest": sha256_file(path),
        }
        for path in manifest_paths
    ]
    return block


def _source_identity(root: Path) -> Dict[str, Any]:
    """Source census over :data:`SOURCE_GLOBS` (same shape as R3's)."""

    entries: List[Tuple[str, str]] = []
    for pattern in SOURCE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            entries.append((str(path.relative_to(root)), sha256_file(path)))
    entries.sort()
    return {
        "globs": list(SOURCE_GLOBS),
        "file_count": len(entries),
        "source_file_list_digest": sha256_canonical(entries),
    }


def _harness_identity(root: Path) -> Dict[str, Any]:
    entries: List[Tuple[str, str]] = []
    for name in HARNESS_MODULES:
        path = root / "caprls_core" / name
        if not path.exists():
            raise SelectionCostError(f"harness module missing: {name}")
        entries.append((name, sha256_file(path)))
    return {
        "modules": [name for name, _ in entries],
        "module_digests": dict(entries),
        "harness_digest": sha256_canonical(entries),
    }


# --------------------------------------------------------------------------
# C2 - runtime-verified E10 excluded tail
# --------------------------------------------------------------------------

#: The exact statements that follow the STOP anchor and precede the reference
#: execution.  Matched by CONTENT at run time; the line numbers in the receipt
#: are therefore MEASURED, never transcribed.
E10_EXCLUDED_TAIL_STATEMENTS = (
    "contract_plan = invocation.occurrence_result",
    "if invocation.production_completed_roots:",
    'raise PostgresError("E10 ordinary runner entered the retired production path")',
    'plan_results[(case.query_id, ADMISSION_FIRST_MODE)] = contract_plan',
    'query_plans[(case.query_id, ADMISSION_FIRST_MODE)] = invocation.query_plan',
)
E10_SELECTION_COMPLETE_COMMENT = (
    "# Selection is complete before this independent reference is executed."
)


def measure_e10_excluded_tail() -> Dict[str, Any]:
    """Locate the excluded tail in the live source and report MEASURED lines.

    Condition C2 requires the excluded-tail citation to be exact.  The audit
    and the memo disagreed by one line, so this harness does not transcribe a
    number from either: it finds the statements by content in the frozen file
    and emits whatever the source actually says, plus enough context for an
    auditor to re-derive it.  A receipt field that cites the wrong lines is
    worse than one that cites none; a field that measures them cannot be wrong.
    """

    from caprls_core import e10_study

    path = Path(inspect.getfile(e10_study))
    lines = path.read_text(encoding="utf-8").splitlines()

    found: List[int] = []
    cursor = 0
    for statement in E10_EXCLUDED_TAIL_STATEMENTS:
        for index in range(cursor, len(lines)):
            if lines[index].strip() == statement:
                found.append(index + 1)
                cursor = index + 1
                break
        else:
            raise SelectionCostError(
                "E10 excluded-tail statement not found in frozen source: "
                + statement
            )
    comment_line = None
    for index in range(cursor, min(cursor + 8, len(lines))):
        if lines[index].strip() == E10_SELECTION_COMPLETE_COMMENT:
            comment_line = index + 1
            break
    if comment_line is None:
        raise SelectionCostError(
            "E10 'Selection is complete' comment not found after the excluded tail"
        )
    if found != sorted(found) or found[-1] - found[0] != len(found) - 1:
        raise SelectionCostError(
            f"E10 excluded tail is not contiguous: {found}"
        )
    lo, hi = found[0], found[-1]
    return {
        "measured_range": f"e10_study.py:{lo}-{hi}",
        "measured_first_line": lo,
        "measured_last_line": hi,
        "statements": list(E10_EXCLUDED_TAIL_STATEMENTS),
        "selection_complete_comment_line": comment_line,
        "contains_io": False,
        "method": "content_matched_against_frozen_source_at_run_time",
        "note": (
            "line numbers are measured from the frozen file at run time, not "
            "transcribed; the tail is one local assignment, one guard and two "
            "dict writes, none of which performs I/O"
        ),
    }


# --------------------------------------------------------------------------
# Per-cell setup ordering, checked structurally
# --------------------------------------------------------------------------

#: The frozen per-cell setup sequence every campaign must reproduce.
#: `caprls_e3_policy_<rel>` is a global, per-relation policy that the frozen
#: runner rewrites for each cell, so a campaign that skips it inherits the
#: previous cell's - or the previous campaign's - policy expression, and the
#: planning-catalog replay then fails with `rls_policy_expression_mismatch`.
E3_PER_CELL_SETUP_ORDER = (
    "_build_artifact",
    "_configure_native_rls",
    "_collect_e3_planning_catalog_receipt",
    "_plan_e3_admission_first",
)


def call_order(func: Any, names: Sequence[str]) -> List[str]:
    """Names from ``names`` in the order they are *called* in ``func``'s source.

    Structural, not behavioural: it reads the AST, so it can assert a setup
    ordering offline, with no database and no execution.
    """

    import ast
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    wanted = set(names)
    found: List[Tuple[int, int, str]] = []
    for node in ast.walk(tree):
        # Any *reference* to the symbol counts, not only a direct call: campaign
        # B reaches `_collect_e3_planning_catalog_receipt` by handing it to a
        # timing helper (`_timed(e3._collect_..., ...)`), which performs the step
        # at exactly that point in the sequence.  String literals never match,
        # so prose mentioning a step name cannot forge one.
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        else:
            continue
        if name in wanted:
            found.append((node.lineno, node.col_offset, name))
    found.sort()
    ordered: List[str] = []
    for _line, _col, name in found:
        if not ordered or ordered[-1] != name:
            ordered.append(name)
    return ordered


def assert_per_cell_setup_order(func: Any, *, label: str) -> List[str]:
    """Refuse a campaign entry point that does not follow the frozen order."""

    observed = call_order(func, E3_PER_CELL_SETUP_ORDER)
    missing = [name for name in E3_PER_CELL_SETUP_ORDER if name not in observed]
    if missing:
        raise SelectionCostError(
            f"{label} omits frozen per-cell setup step(s): {missing}. "
            "A campaign that skips _configure_native_rls inherits the previous "
            "cell's RLS policy expression and its planning-catalog replay fails "
            "with rls_policy_expression_mismatch."
        )
    expected = [name for name in E3_PER_CELL_SETUP_ORDER if name in observed]
    if observed != expected:
        raise SelectionCostError(
            f"{label} performs the frozen per-cell setup out of order: "
            f"{observed} != {expected}"
        )
    return observed


# --------------------------------------------------------------------------
# C1 - adaptive top-k assertion
# --------------------------------------------------------------------------


def assert_adaptive_topk_disabled(root: Path, manifest: Mapping[str, Any]) -> Dict[str, Any]:
    """C1: read ``adaptive_topk`` from the manifest, assert disabled, record it.

    ``run_e3_main`` calls ``_apply_adaptive_topk`` AFTER
    ``_plan_e3_admission_first`` returns and before the repetition loop, and that
    function can re-filter accepted candidates.  The E3 anchor is therefore
    complete only while adaptive top-k is off.  Evidence beats inheritance.
    """

    from caprls_core import e3_main as e3

    config = e3._adaptive_topk_from_manifest(manifest)
    enabled = bool(getattr(config, "enabled", False))
    dedup = bool(getattr(config, "deduplicate_plan_shapes", False))
    if enabled:
        raise SelectionCostError(
            "C1 refusal: adaptive_topk is enabled for this manifest, so "
            "_apply_adaptive_topk may rewrite the selection after the anchor "
            "closes; the E3 selection-wall anchor would be incomplete"
        )
    if dedup:
        # Same defect class as C1, one field over.  `run_e3_main` also calls
        # `_deduplicate_equivalent_plan_shapes(enabled=adaptive_topk
        # .deduplicate_plan_shapes)` after the anchor closes.  That helper
        # documents itself as shadow-only, but "documented as harmless" is
        # exactly the inheritance C1 forbids, so assert it too.
        raise SelectionCostError(
            "C1 refusal (extended): adaptive_topk.deduplicate_plan_shapes is "
            "enabled; a post-anchor plan-shape pass would run outside the "
            "selection-wall bracket"
        )
    return {
        "adaptive_topk_enabled": False,
        "adaptive_topk_deduplicate_plan_shapes": False,
        "adaptive_topk_declared_in_manifest": "adaptive_topk" in dict(manifest),
        "config_repr": repr(config),
        "asserted_at": "run_time_from_manifest",
        "post_anchor_steps_asserted_noop": [
            "caprls_core.e3_main._apply_adaptive_topk",
            "caprls_core.e3_main._deduplicate_equivalent_plan_shapes",
        ],
        "why": (
            "_apply_adaptive_topk runs after _plan_e3_admission_first returns "
            "and can re-filter accepted candidates; the anchor is complete "
            "only while it and the plan-shape pass are no-ops"
        ),
    }


# --------------------------------------------------------------------------
# Derived quantities: tie band, break-even (C6), amortization
# --------------------------------------------------------------------------


def outcome(ratio: float) -> str:
    """Frozen W/T/L rule - ``e3_scale_check.py:101-104``."""

    return "win" if ratio > TIE_FACTOR else ("loss" if ratio < TIE_LOWER_BOUND else "tie")


def tie_class(q_native_ms: float, q_ca_ms: float) -> Tuple[str, float]:
    ratio = q_native_ms / q_ca_ms
    return outcome(ratio), ratio


def break_even(
    selection_wall_ms: float,
    q_ca_ms: float,
    q_native_ms: float,
) -> Dict[str, Any]:
    """Per-cell break-even.

    C6 is enforced structurally: ``break_even_k`` is only ever produced inside
    this dict, which always carries ``within_tie_band`` beside it.  Nothing in
    this package can emit one without the other -
    :func:`assert_break_even_paired` re-checks it before any write.
    """

    klass, ratio = tie_class(q_native_ms, q_ca_ms)
    delta = q_native_ms - q_ca_ms
    if delta > 0:
        k = int(math.ceil(selection_wall_ms / delta))
        payload = {
            "break_even_k": k,
            "break_even_class": "finite",
            "within_tie_band": klass == "tie",
        }
    else:
        payload = {
            "break_even_k": None,
            "break_even_class": "no_finite_break_even",
            "within_tie_band": klass == "tie",
        }
    payload.update(
        {
            "delta_ms": delta,
            "ratio_native_over_ca": ratio,
            "tie_class": klass,
            "tie_band": {"lower": TIE_LOWER_BOUND, "upper": TIE_FACTOR},
            "selection_wall_ms_used": selection_wall_ms,
            "q_ca_ms": q_ca_ms,
            "q_native_ms": q_native_ms,
        }
    )
    return payload


def assert_break_even_paired(payload: Mapping[str, Any]) -> None:
    """C6 guard - refuse to write a ``break_even_k`` without its band flag."""

    if "break_even_k" in payload and "within_tie_band" not in payload:
        raise SelectionCostError(
            "C6 violation: break_even_k emitted without within_tie_band"
        )


def amortization(
    selection_wall_ms: float,
    q_ca_ms: float,
    q_native_ms: float,
    k_grid: Sequence[int] = K_GRID,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for k in k_grid:
        amortized = q_ca_ms + selection_wall_ms / float(k)
        ratio = q_native_ms / amortized
        rows.append(
            {
                "k": int(k),
                "amortized_ca_ms": amortized,
                "ratio_k": ratio,
                "outcome_k": outcome(ratio),
            }
        )
    return rows


def k_star_grid(rows: Sequence[Mapping[str, Any]]) -> Optional[int]:
    for row in rows:
        if row["outcome_k"] == "win":
            return int(row["k"])
    return None


def _median(values: Sequence[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def _p(values: Sequence[float], q: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def distribution(values: Sequence[float]) -> Dict[str, Any]:
    vals = [float(v) for v in values]
    return {
        "observation_count": len(vals),
        "median": _median(vals),
        "min": min(vals) if vals else None,
        "p10_linear": _p(vals, 0.10),
        "p90_linear": _p(vals, 0.90),
        "max": max(vals) if vals else None,
        "samples": vals,
    }


def family_aggregate(cells: Sequence[Mapping[str, Any]], *, k: int) -> Dict[str, Any]:
    """W/T/L + median + geometric mean of ratio(k) over a set of cells."""

    ratios: List[float] = []
    counts = {"win": 0, "tie": 0, "loss": 0}
    extremes: List[Tuple[float, str]] = []
    for cell in cells:
        row = next(r for r in cell["derived"]["amortization"] if r["k"] == k)
        ratios.append(float(row["ratio_k"]))
        counts[row["outcome_k"]] += 1
        extremes.append((float(row["ratio_k"]), cell["short_id"]))
    if not ratios:
        return {"k": k, "cell_count": 0}
    lo = min(extremes)
    hi = max(extremes)
    return {
        "k": k,
        "cell_count": len(ratios),
        "wins": counts["win"],
        "ties": counts["tie"],
        "losses": counts["loss"],
        "wtl": f"{counts['win']}/{counts['tie']}/{counts['loss']}",
        "ratio_median": statistics.median(ratios),
        "ratio_geometric_mean": statistics.geometric_mean(ratios),
        "ratio_min": lo[0],
        "ratio_min_cell": lo[1],
        "ratio_max": hi[0],
        "ratio_max_cell": hi[1],
        "ratio_definition": "Q_N / (Q_CA + selection_wall_ms / k)",
    }


def pooled_aggregate(
    e3_cells: Sequence[Mapping[str, Any]],
    e10_cells: Sequence[Mapping[str, Any]],
    *,
    k: int,
) -> Optional[Dict[str, Any]]:
    """C3 + C4: pooled 44-cell aggregate on the COMMENSURABLE pairing only.

    The commensurable pairing is E3 ``selection_wall_plus_inputs_ms`` against
    E10 ``selection_wall_ms``: E10's bracket contains the planning inputs that
    E3's excludes, so pooling the two declared primaries would pool a quantity
    of different extent.  If any E3 cell lacks ``selection_wall_plus_inputs_ms``
    the pooled row is **not produced at all** - the audit's stated alternative.

    Both labels required by C4 are written into the returned dict; there is no
    code path that produces a pooled figure without them.

    **Family-representation guard.** A pooled row must also be pooled *over both
    families*. The first implementation only checked per-cell field presence, so
    an E10-only partial run emitted a row labelled "pooled across two dissimilar
    families" that was computed from eleven E10 cells and zero E3 cells, naming
    an E3 pairing that contributed nothing. That is exactly the mislabelling C3
    exists to prevent, so representation is now a precondition, checked by
    :func:`pooled_omission_reason`.
    """

    reason = pooled_omission_reason(e3_cells, e10_cells)
    if reason is not None:
        return None

    ratios: List[float] = []
    counts = {"win": 0, "tie": 0, "loss": 0}
    extremes: List[Tuple[float, str]] = []
    for cell in list(e3_cells) + list(e10_cells):
        wall = cell["derived"].get("pooled_commensurable_wall_ms")
        if wall is None:
            return None
        q_ca = cell["derived"]["Q_CA_ms"]
        q_native = cell["derived"]["Q_N_ms"]
        ratio = q_native / (q_ca + wall / float(k))
        ratios.append(ratio)
        counts[outcome(ratio)] += 1
        extremes.append((ratio, cell["short_id"]))
    if not ratios:
        return None
    lo, hi = min(extremes), max(extremes)
    return {
        "k": k,
        "cell_count": len(ratios),
        "wins": counts["win"],
        "ties": counts["tie"],
        "losses": counts["loss"],
        "wtl": f"{counts['win']}/{counts['tie']}/{counts['loss']}",
        "ratio_median": statistics.median(ratios),
        "ratio_geometric_mean": statistics.geometric_mean(ratios),
        "ratio_min": lo[0],
        "ratio_min_cell": lo[1],
        "ratio_max": hi[0],
        "ratio_max_cell": hi[1],
        # C3 - the row is self-evidencing about who contributed to it.
        "pooled_family_cell_counts": {"E3": len(e3_cells), "E10": len(e10_cells)},
        "pooled_commensurable_pairing": POOLED_COMMENSURABLE_PAIRING,
        # C4 - both labels, structurally inseparable
        "aggregation_scope": POOLED_AGGREGATION_SCOPE,
        "pooled_measurand_scope_mismatch": POOLED_MEASURAND_SCOPE_MISMATCH,
    }


def pooled_omission_reason(
    e3_cells: Sequence[Mapping[str, Any]],
    e10_cells: Sequence[Mapping[str, Any]],
) -> Optional[str]:
    """C3: why a pooled row must not be published, or ``None`` if it may be.

    Two independent grounds, both of which omit the row entirely:

    1. **family representation** - a figure labelled "pooled across two
       dissimilar families" must actually contain cells from both;
    2. **commensurability** - every contributing cell must supply
       ``pooled_commensurable_wall_ms`` (E3 ``selection_wall_plus_inputs_ms``,
       E10 ``selection_wall_ms``), because pooling the two declared primaries
       would pool a quantity of different extent.
    """

    if not e3_cells and not e10_cells:
        return "C3: no measured cells, so no pooled row is published"
    if not e3_cells:
        return (
            "C3: no E3 cell contributed, so a figure labelled as pooled across "
            "two families would be an E10-only aggregate under a pooled label"
        )
    if not e10_cells:
        return (
            "C3: no E10 cell contributed, so a figure labelled as pooled across "
            "two families would be an E3-only aggregate under a pooled label"
        )
    for cell in list(e3_cells) + list(e10_cells):
        if cell["derived"].get("pooled_commensurable_wall_ms") is None:
            return (
                "C3: at least one cell could not supply the commensurable "
                f"quantity ({cell.get('short_id')}), so no pooled row is published"
            )
    return None


def assert_pooled_labels_present(payload: Mapping[str, Any]) -> None:
    """C4 guard - any pooled figure must carry both labels."""

    for key in ("aggregation_scope", "pooled_measurand_scope_mismatch",
                "pooled_commensurable_pairing"):
        if not payload.get(key):
            raise SelectionCostError(
                f"C4 violation: pooled figure emitted without {key}"
            )


# --------------------------------------------------------------------------
# Package IO and sealing
# --------------------------------------------------------------------------


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], columns: Sequence[str]) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def package_is_sealed(run_dir: Path) -> bool:
    return (run_dir / "INTEGRITY.json").exists() and (run_dir / "IMMUTABLE").exists()


def seal_package(
    run_dir: Path,
    *,
    summary: Mapping[str, Any],
    summary_rows: Sequence[Mapping[str, Any]],
    summary_columns: Sequence[str],
    status: str,
) -> Dict[str, Any]:
    """Seal in the R3 order (``content_verify._finalize_run``: IMMUTABLE ->
    summary.json -> summary.csv -> MANIFEST.sha256 -> INTEGRITY.json -> chmod).

    The Merkle root is computed exactly once, last, over a set that excludes
    both ``MANIFEST.sha256`` and ``INTEGRITY.json``, and is deliberately not
    written back into ``summary.json``.
    """

    run_dir.mkdir(parents=True, exist_ok=True)
    seal = {
        "sealed_at": utc_now(),
        "status": status,
        "campaign": summary.get("campaign"),
    }
    (run_dir / "IMMUTABLE").write_text(
        json.dumps(seal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    payload = dict(summary)
    payload["seal"] = seal
    write_json(run_dir / "summary.json", payload)
    write_csv(run_dir / "summary.csv", summary_rows, summary_columns)
    integrity = cv.write_manifest_and_merkle(run_dir)
    write_json(run_dir / "INTEGRITY.json", integrity)
    readonly = cv._apply_readonly(run_dir)
    return {"seal": seal, "integrity": integrity, "readonly": readonly}


def failure_record(
    short_id: str,
    *,
    phase: str,
    exc: BaseException,
    failure_class: str = "cell_failure",
    partial: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "schema": "caprls-selection-cost-failure-v1",
        "short_id": short_id,
        "status": "failed",
        "failure_class": failure_class,
        "phase": phase,
        "exception_class": exc.__class__.__name__,
        "exception_message": str(exc)[:8000],
        "recorded_at": utc_now(),
        "partial": dict(partial or {}),
    }


@dataclass
class StopRule:
    """Systematic-failure stop rules (memo section 10.2)."""

    family_cell_count: int
    consecutive_failures: int = 0
    total_failures: int = 0

    def record_success(self) -> None:
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        self.total_failures += 1

    def should_stop(self) -> Optional[str]:
        if self.consecutive_failures >= 3:
            return "three_consecutive_cell_failures"
        if self.family_cell_count and (
            self.total_failures / float(self.family_cell_count) > 0.20
        ):
            return "more_than_20_percent_of_family_cells_failed"
        return None


# --------------------------------------------------------------------------
# Pass-through observation wrappers (restored in finally, always)
# --------------------------------------------------------------------------


class PassThroughWrapper:
    """Install an exception-proof observing wrapper on a frozen function.

    Modelled on the Gate-approved ``content_verify._E3CostVectorCapture``
    (``content_verify.py:852-899``): the wrapper records in passing, delegates
    unchanged, swallows every observation error, and restores the original
    binding in ``finally``.  It can never alter the wrapped function's
    behaviour or its result.
    """

    def __init__(self, module: Any, name: str, observer: Callable[..., None]) -> None:
        self._module = module
        self._name = name
        self._observer = observer
        self._original: Any = None
        self.calls = 0

    def __enter__(self) -> "PassThroughWrapper":
        self._original = getattr(self._module, self._name)
        original = self._original
        observer = self._observer
        counter = self

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            counter.calls += 1
            caller = sys._getframe(1)
            started = _perf()
            try:
                observer("enter", caller, started, None, args, kwargs)
            except Exception:  # noqa: BLE001 - observation must never perturb
                pass
            result = original(*args, **kwargs)
            try:
                observer("exit", caller, _perf(), result, args, kwargs)
            except Exception:  # noqa: BLE001
                pass
            return result

        setattr(self._module, self._name, _wrapper)
        return self

    def __exit__(self, *exc_info: Any) -> None:
        setattr(self._module, self._name, self._original)


def _perf() -> float:
    import time

    return time.perf_counter()


def caller_name(frame: Any) -> str:
    try:
        return frame.f_code.co_name
    except Exception:  # noqa: BLE001 - defensive
        return "<unknown>"
