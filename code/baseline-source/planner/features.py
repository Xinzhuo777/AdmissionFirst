"""Planner switches that are exercised by the current implementation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Literal, Mapping


FeatureMode = Literal["enabled", "disabled", "shadow"]


@dataclass(frozen=True)
class PlannerFeatureFlags:
    feasibility_backtracking: bool = True
    reference_dominance: FeatureMode = "enabled"

    def __post_init__(self) -> None:
        valid = {"enabled", "disabled", "shadow"}
        for name, value in asdict(self).items():
            if name == "feasibility_backtracking":
                if not isinstance(value, bool):
                    raise TypeError("feasibility_backtracking must be bool")
                continue
            if value not in valid:
                raise ValueError(f"invalid planner feature mode for {name}: {value!r}")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        require_complete: bool = False,
    ) -> "PlannerFeatureFlags":
        """Parse a feature mapping without accepting misspelled switches."""

        if not isinstance(payload, Mapping):
            raise TypeError("planner feature flags must be a mapping")
        known = {item.name for item in fields(cls)}
        observed = {str(key) for key in payload}
        unknown = sorted(observed - known)
        if unknown:
            raise ValueError("unknown planner feature flags: " + ", ".join(unknown))
        if require_complete:
            missing = sorted(known - observed)
            if missing:
                raise ValueError("incomplete planner feature contract: " + ", ".join(missing))
        return cls(**{str(key): value for key, value in payload.items()})


DEFAULT_PLANNER_FEATURE_FLAGS = PlannerFeatureFlags()
