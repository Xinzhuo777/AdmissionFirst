"""Opt-in, sparse selection diagnostics; never changes SQL or planner policy.

This module temporarily observes named call boundaries, including loaded
``from ... import`` aliases.  It does not install a global Python profiler.
Exclusive categories partition one external call's wall time; inclusive
function times are diagnostics and must not be added together.  In particular,
the complete strict-planning adapter is *not* labelled admission/checker time.
Use in a single-threaded diagnostic process, not a production request worker.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
import importlib
import re
import sys
import threading
import time
from typing import Any, Callable, Iterator

CATEGORIES = (
    "admission", "certificate_checker", "candidate_construction",
    "postgres_explain", "database_other", "selection_other",
)
CATEGORY_DEFINITIONS = {
    "admission": "ContractChecker.check and named typed-admission derivation/replay boundaries",
    "certificate_checker": "actual certificate check/replay and SQL/EXPLAIN static-check boundaries; excludes certificate generation",
    "candidate_construction": "remaining query/strict candidate construction, lowering and SQL composition",
    "postgres_explain": "plain EXPLAIN client-call window including transport and named costing-call parsing; not PostgreSQL-only planning time",
    "database_other": "session/process startup and all other observed database calls",
    "selection_other": "root selection/binding plus all unassigned time and sparse-hook bookkeeping",
}

_MODULE_FUNCTIONS = {
    "planner.core": {
        "admission": ("_typed_target_admission",),
        "candidate_construction": ("plan",),
    },
    "planner.query": {"candidate_construction": ("plan_query", "_query_certificate_and_check")},
    "planner.strict_planning": {
        "candidate_construction": ("strict_plan_forced_alternative", "_strict_plan_query_impl"),
    },
    "planner.certificate_envelope": {
        "admission": ("derive_typed_admission_bindings",),
        "candidate_construction": ("derive_strict_certificate_steps", "build_certificate_envelope",
                                   "conditionally_checked_from_replay"),
        "certificate_checker": ("replay_certificate_envelope",),
    },
    "planner.certificates": {
        "candidate_construction": ("emit_query_certificate", "emit_flat_certificate"),
    },
    "planner.verifier.cert_checker": {"certificate_checker": ("check_certificate",)},
    "planner.root_selection": {
        "selection_other": ("select_completed_roots",),
    },
    "planner.emit": {"candidate_construction": ("emit_sql",)},
}


@dataclass
class _Frame:
    category: str
    label: str
    started_ns: int
    child_ns: int = 0


def classify_sql(sql: str) -> str:
    """Classify without altering or executing a statement."""
    # Database session.execute accepts one statement; comments may precede it.
    prefix = re.sub(r"\A(?:\s+|--[^\n]*(?:\n|$)|/\*.*?\*/)*", "", str(sql), flags=re.S)
    # E10's frozen costing helper sends these three SETs and one EXPLAIN in
    # the same psql call. Recognize only its exact finite GUC preamble, never
    # search an arbitrary script/string literal for the word EXPLAIN.
    prefix = re.sub(r"\A(?:SET\s+(?:jit|max_parallel_workers_per_gather|plan_cache_mode)\s*=\s*[A-Za-z0-9_]+\s*;\s*)+",
                    "", prefix, flags=re.I)
    if not re.match(r"EXPLAIN\b", prefix, flags=re.I):
        return "other"
    options = prefix[len("EXPLAIN"):].lstrip()
    option_prefix = options.split(")", 1)[0] if options.startswith("(") else options.split(None, 1)[0]
    analyze = re.search(r"\bANALY[ZS]E\b(?:\s+([\w]+))?", option_prefix, flags=re.I)
    if analyze is not None and str(analyze.group(1)).lower() not in ("false", "off", "0"):
        return "explain_analyze"
    return "plain_explain"


class SelectionCostBreakdown:
    """Restore every temporary hook on success or exception.

    ``result, summary = SelectionCostBreakdown(family='E3').run(fn, **kw)``
    measures exactly one invocation.  ``with collector: collector.run(...)``
    permits repeated independent observations without reinstalling the hooks.
    Existing sys.getprofile() state is never changed.  Sparse-hook overhead is
    included, not silently subtracted or inferred from historical measurements.
    """

    _owner: "SelectionCostBreakdown | None" = None

    def __init__(self, family: str = "E3", *, clock_ns: Callable[[], int] = time.perf_counter_ns):
        if family not in ("E3", "E10"):
            raise ValueError("family must be E3 or E10")
        self.family, self._clock_ns = family, clock_ns
        self._patches: list[tuple[Any, str, Any]] = []
        self._entered = self._running = False
        self._thread_id: int | None = None
        self._inventory: list[str] = []
        self._hooks_by_category: dict[str, list[str]] = {key: [] for key in CATEGORIES}
        self._sql_hooks: list[str] = []
        self.last_summary: dict[str, Any] | None = None
        self._reset()

    def _reset(self) -> None:
        self._stack: list[_Frame] = []
        self._exclusive_ns = dict.fromkeys(CATEGORIES, 0)
        self._inclusive_ns = dict.fromkeys(CATEGORIES, 0)
        self._counts = dict.fromkeys(CATEGORIES, 0)
        self._functions: dict[str, dict[str, int]] = {}
        self._sql_counts = dict.fromkeys(("plain_explain", "explain_analyze", "other"), 0)

    @contextmanager
    def scope(self, category: str, label: str) -> Iterator[None]:
        """Named nested observation; available for unit tests/external adapters."""
        if category not in CATEGORIES:
            raise ValueError(f"unknown category: {category}")
        if not self._running or threading.get_ident() != self._thread_id:
            yield
            return
        frame = _Frame(category, label, self._clock_ns())
        self._stack.append(frame)
        try:
            yield
        finally:
            elapsed = self._clock_ns() - frame.started_ns
            self._stack.pop()
            if elapsed < frame.child_ns:
                raise RuntimeError("non-monotonic timer or invalid nested measurement")
            exclusive = elapsed - frame.child_ns
            self._inclusive_ns[category] += elapsed
            self._exclusive_ns[category] += exclusive
            self._counts[category] += 1
            stats = self._functions.setdefault(label, {"calls": 0, "inclusive_ns": 0, "exclusive_ns": 0})
            stats["calls"] += 1
            stats["inclusive_ns"] += elapsed
            stats["exclusive_ns"] += exclusive
            if self._stack:
                self._stack[-1].child_ns += elapsed

    def _wrapper(self, original: Callable[..., Any], category: str, label: str,
                 sql_index: int | None = None) -> Callable[..., Any]:
        @wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            if not self._running or threading.get_ident() != self._thread_id:
                return original(*args, **kwargs)
            actual = category
            if sql_index is not None:
                sql = args[sql_index] if len(args) > sql_index else kwargs.get("sql", "")
                kind = classify_sql(sql)
                self._sql_counts[kind] += 1
                # EXPLAIN ANALYZE is surfaced separately as a red flag: it is
                # diagnostic execution, not prospective plain costing.
                actual = "postgres_explain" if kind == "plain_explain" else "database_other"
            with self.scope(actual, label):
                return original(*args, **kwargs)
        observed._caprls_observation_category = category
        observed._caprls_observation_label = label
        observed._caprls_observation_sql = sql_index is not None
        return observed

    def _patch(self, owner: Any, name: str, original: Any, wrapper: Any) -> None:
        self._patches.append((owner, name, original))
        setattr(owner, name, wrapper)
        self._inventory.append(f"{getattr(owner, '__name__', type(owner).__name__)}.{name}")
        category = wrapper._caprls_observation_category
        label = wrapper._caprls_observation_label
        if label not in self._hooks_by_category[category]:
            self._hooks_by_category[category].append(label)
        if wrapper._caprls_observation_sql:
            if label not in self._sql_hooks:
                self._sql_hooks.append(label)
            if label not in self._hooks_by_category["postgres_explain"]:
                self._hooks_by_category["postgres_explain"].append(label)

    def _install(self) -> None:
        modules = {name: importlib.import_module(name) for name in _MODULE_FUNCTIONS}
        family_module = importlib.import_module("caprls_core.e3_main" if self.family == "E3" else "caprls_core.e10_study")
        pg = importlib.import_module("caprls_core.postgres_runner")
        targets: dict[Any, tuple[str, str, int | None]] = {}
        for name, groups in _MODULE_FUNCTIONS.items():
            for category, names in groups.items():
                for function_name in names:
                    original = getattr(modules[name], function_name, None)
                    if callable(original):
                        targets[original] = (category, f"{name}.{function_name}", None)
        for name in ("_e3_planning_problem", "_e3_planning_query", "_e3_bound_runner_sql",
                     "_e3_continuation_spec", "_e10_planning_problem", "_e10_planning_query",
                     "_e10_bound_runner_sql", "_e10_continuation_spec",
                     "_planning_problem_for_case", "_planning_query_for_case"):
            original = getattr(family_module, name, None)
            if callable(original):
                targets[original] = ("candidate_construction", f"{family_module.__name__}.{name}", None)
        for name in ("_require_e3_typed_admission_bundle", "_require_e10_typed_admission_bundle"):
            original = getattr(family_module, name, None)
            if callable(original):
                targets[original] = ("admission", f"{family_module.__name__}.{name}", None)
        for name in ("_verify_e3_static", "_verify_e10_static", "_verify_static_template"):
            original = getattr(family_module, name, None)
            if callable(original):
                targets[original] = ("certificate_checker", f"{family_module.__name__}.{name}", None)
        original = getattr(family_module, "_prospective_pg_cost", None)
        if callable(original):
            targets[original] = ("postgres_explain", f"{family_module.__name__}._prospective_pg_cost", None)
        # These identity/binding guards are deliberately not labelled the
        # certificate checker. Named windows expose previously unassigned work.
        for name in ("_require_e3_production_planning_owner", "_require_e10_production_planning_owner"):
            original = getattr(family_module, name, None)
            if callable(original):
                targets[original] = ("selection_other", f"{family_module.__name__}.{name}", None)
        targets[pg.run_psql_command] = ("database_other", "caprls_core.postgres_runner.run_psql_command", 0)
        wrappers = {fn: self._wrapper(fn, *spec) for fn, spec in targets.items()}
        # Match aliases by identity, never by an ambiguous short name. Import
        # installation occurs outside the reported invocation's time window.
        for module in tuple(sys.modules.values()):
            if module is None or not getattr(module, "__name__", "").startswith(("planner", "caprls_core")):
                continue
            for name, value in tuple(vars(module).items()):
                if not callable(value):
                    continue
                try:
                    wrapper = wrappers.get(value)
                except TypeError:
                    continue
                if wrapper is not None:
                    self._patch(module, name, value, wrapper)
        checker = modules["planner.core"].ContractChecker
        self._patch(checker, "check", checker.check, self._wrapper(checker.check, "admission", "planner.core.ContractChecker.check"))
        for cls, method, category, sql_index in (
            (pg.PostgresTransactionSession, "__init__", "database_other", None),
            (pg.PostgresTransactionSession, "execute", "database_other", None),
            (pg._PsqlInteractiveChannel, "execute", "database_other", 1),
        ):
            original = getattr(cls, method)
            self._patch(cls, method, original, self._wrapper(original, category, f"{cls.__module__}.{cls.__name__}.{method}", sql_index))

    def __enter__(self) -> "SelectionCostBreakdown":
        if self._entered or SelectionCostBreakdown._owner is not None:
            raise RuntimeError("selection breakdown contexts cannot overlap")
        SelectionCostBreakdown._owner = self
        self._inventory.clear()
        self._hooks_by_category = {key: [] for key in CATEGORIES}
        self._sql_hooks.clear()
        try:
            self._install()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        self._entered = True
        return self

    def __exit__(self, *exc: Any) -> None:
        for owner, name, original in reversed(self._patches):
            setattr(owner, name, original)
        self._patches.clear()
        self._entered = False
        SelectionCostBreakdown._owner = None

    def start_window(self) -> None:
        """Begin a contiguous external window after hooks have been installed.

        Used by the unchanged E10 START/STOP anchors; it must not begin only
        at the inner planner and thereby omit original planning inputs.
        """
        if not self._entered:
            raise RuntimeError("start_window requires an entered collector")
        if self._running:
            raise RuntimeError("selection observation windows cannot nest")
        self._reset()
        self._running = True
        self._thread_id = threading.get_ident()
        self._started_ns = self._clock_ns()

    def stop_window(self) -> dict[str, Any]:
        """Stop before metadata serialization/flush; retain exclusive conservation."""
        if not self._running:
            raise RuntimeError("STOP has no matching open selection window")
        total = self._clock_ns() - self._started_ns
        self._running = False
        if self._stack:
            raise RuntimeError("selection window stopped inside an observed function")
        residual = total - sum(self._exclusive_ns.values())
        if residual < 0:
            raise RuntimeError("exclusive categories exceed external wall time")
        self._exclusive_ns["selection_other"] += residual
        exclusive = {key: value / 1e6 for key, value in self._exclusive_ns.items()}
        self.last_summary = {
            "schema": "caprls-selection-cost-breakdown-v1", "family": self.family,
            "total_wall_ms": total / 1e6, "exclusive_ms": exclusive,
            "inclusive_ms": {key: value / 1e6 for key, value in self._inclusive_ns.items()},
            "call_counts": dict(self._counts), "counts": dict(self._counts),
            "functions": {key: {"calls": value["calls"], "inclusive_ms": value["inclusive_ns"] / 1e6,
                                "exclusive_ms": value["exclusive_ns"] / 1e6} for key, value in self._functions.items()},
            "sql_call_counts": dict(self._sql_counts),
            "conservation_error_ms": (sum(self._exclusive_ns.values()) - total) / 1e6,
            "hook_inventory": list(self._inventory),
            "category_definitions": dict(CATEGORY_DEFINITIONS),
            "global_profile_modified": False, "sparse_observer_overhead_included": True,
            "inclusive_not_additive": True,
            "uncategorized_assigned_to_selection_other_ms": residual / 1e6,
            "coverage": {
                category: {
                    "status": "observed" if self._counts[category] > 0 or (category == "selection_other" and residual > 0) else "not_applicable",
                    "calls": self._counts[category], "hooks_installed": list(self._hooks_by_category[category]),
                    "reason": ("external_window_remainder_measured; no named selection_other hook invoked"
                               if category == "selection_other" and self._counts[category] == 0 and residual > 0
                               else "named boundaries observed" if self._counts[category] > 0
                               else "no calls to this category's installed named boundaries in the original selection window"),
                } for category in CATEGORIES
            },
            "sql_coverage": {
                kind: {"status": "observed" if count > 0 else "not_applicable", "calls": count,
                       "hooks_installed": list(self._sql_hooks),
                       "reason": "matching SQL calls observed" if count > 0 else "no matching SQL call in the original selection window"}
                for kind, count in self._sql_counts.items()
            },
        }
        return self.last_summary

    def run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
        if not self._entered:
            with self:
                return self.run(fn, *args, **kwargs)
        self.start_window()
        try:
            result = fn(*args, **kwargs)
        finally:
            self.stop_window()
        return result, self.last_summary
