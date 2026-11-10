"""Exhaustive finite-frontier reference used by G5b/G5c verification.

This module deliberately knows nothing about cost or PostgreSQL.  It expands a
small finite product in canonical occurrence/alternative order and records
whether the entire declared search space was inspected.  Query integration
uses the first legal result only for G5b feasibility; choosing the cheapest
among already legal alternatives is a separate, shadow-only G5c concern.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from math import prod
from typing import Callable, Generic, Mapping, Sequence, TypeVar


T = TypeVar("T")

# ``FiniteFrontierResult.combinations`` is diagnostic evidence only; it must
# never become a second materialization of the semantic search space.  The
# search itself remains exhaustive (unless its explicit budget fires), while
# this trace keeps a bounded prefix and advertises whether it is complete.
_MAX_COMBINATION_TRACE = 256


@dataclass(frozen=True)
class FiniteFrontierEvidence:
    status: str
    explored_combinations: int
    total_combinations: int
    search_budget: int | None
    legal_combination_index: int | None = None
    # ``skip_first`` is only safe when the caller has already validated the
    # local incumbent.  Count that validation explicitly so a complete result
    # still accounts for the declared, rather than merely remaining, product.
    prechecked_combinations: int = 0

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete"}:
            raise ValueError("finite frontier status must be complete or incomplete")
        if self.explored_combinations < 0 or self.total_combinations < 0:
            raise ValueError("finite frontier counts cannot be negative")
        if self.search_budget is not None and self.search_budget < 0:
            raise ValueError("finite frontier budget cannot be negative")
        if self.legal_combination_index is not None and self.legal_combination_index < 0:
            raise ValueError("legal combination index cannot be negative")
        if self.prechecked_combinations < 0:
            raise ValueError("prechecked combination count cannot be negative")
        if self.explored_combinations + self.prechecked_combinations > self.total_combinations:
            raise ValueError("frontier evidence cannot inspect more than its declared product")
        if self.status == "complete" and (
            self.explored_combinations + self.prechecked_combinations
            != self.total_combinations
        ):
            raise ValueError("complete frontier evidence must account for every combination")
        if (
            self.legal_combination_index is not None
            and self.legal_combination_index >= self.total_combinations
        ):
            raise ValueError("legal combination index exceeds the declared product")

    @property
    def search_complete(self) -> bool:
        return self.status == "complete"


@dataclass(frozen=True)
class FiniteFrontierResult(Generic[T]):
    occurrence_ids: tuple[str, ...]
    combinations: tuple[tuple[T, ...], ...]
    combinations_complete: bool
    first_legal: tuple[T, ...] | None
    evidence: FiniteFrontierEvidence


def exhaustive_first_feasible(
    alternatives_by_occurrence: Mapping[str, Sequence[T]],
    *,
    is_legal: Callable[[tuple[T, ...]], bool],
    search_budget: int | None = None,
    skip_first: bool = False,
) -> FiniteFrontierResult[T]:
    """Enumerate the frozen finite product and return its first legal point.

    ``skip_first`` supports G5b's invariant that the caller has already
    checked the historical local incumbent.  It is not a heuristic: the
    omitted first point is accounted for as ``prechecked_combinations``.
    ``combinations`` is only a bounded diagnostic prefix; its
    ``combinations_complete`` flag prevents that prefix from being confused
    with search-completeness evidence.  A ``complete`` result is emitted only
    after every remaining point has been evaluated; finding an early legal
    point does not by itself justify a complete-frontier claim.
    """

    if any(not isinstance(key, str) for key in alternatives_by_occurrence):
        raise TypeError("frontier occurrence IDs must be strings")
    if search_budget is not None and search_budget < 0:
        raise ValueError("finite frontier budget cannot be negative")
    occurrence_ids = tuple(sorted(alternatives_by_occurrence))
    option_sets = tuple(tuple(alternatives_by_occurrence[key]) for key in occurrence_ids)
    if any(not options for options in option_sets):
        return FiniteFrontierResult(
            occurrence_ids=occurrence_ids,
            combinations=(),
            combinations_complete=True,
            first_legal=None,
            evidence=FiniteFrontierEvidence(
                status="complete",
                explored_combinations=0,
                total_combinations=0,
                search_budget=search_budget,
                prechecked_combinations=0,
            ),
        )
    total_combinations = prod(len(options) for options in option_sets)
    combinations_iter = iter(product(*option_sets))
    combination_trace: list[tuple[T, ...]] = []

    def record_trace(combination: tuple[T, ...]) -> None:
        if len(combination_trace) < _MAX_COMBINATION_TRACE:
            combination_trace.append(combination)

    explored = 0
    start = 1 if skip_first and total_combinations else 0
    prechecked = 1 if start else 0
    if prechecked:
        # Account for the caller-validated incumbent without evaluating it a
        # second time.  ``product`` advances by one tuple only; no product is
        # materialized before the budget gate below.
        record_trace(next(combinations_iter))
    first_legal: tuple[T, ...] | None = None
    legal_combination_index: int | None = None
    for index in range(start, total_combinations):
        if search_budget is not None and explored >= search_budget:
            return FiniteFrontierResult(
                occurrence_ids=occurrence_ids,
                combinations=tuple(combination_trace),
                combinations_complete=len(combination_trace) == total_combinations,
                first_legal=first_legal,
                evidence=FiniteFrontierEvidence(
                    status="incomplete",
                    explored_combinations=explored,
                    total_combinations=total_combinations,
                    search_budget=search_budget,
                    legal_combination_index=legal_combination_index,
                    prechecked_combinations=prechecked,
                ),
            )
        combination = next(combinations_iter)
        record_trace(combination)
        explored += 1
        if is_legal(combination) and first_legal is None:
            first_legal = combination
            legal_combination_index = index
    return FiniteFrontierResult(
        occurrence_ids=occurrence_ids,
        combinations=tuple(combination_trace),
        combinations_complete=len(combination_trace) == total_combinations,
        first_legal=first_legal,
        evidence=FiniteFrontierEvidence(
            status="complete",
            explored_combinations=explored,
            total_combinations=total_combinations,
            search_budget=search_budget,
            legal_combination_index=legal_combination_index,
            prechecked_combinations=prechecked,
        ),
    )
