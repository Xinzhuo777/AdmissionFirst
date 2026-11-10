"""Shared measurement-repetition protocol helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableMapping


@dataclass(frozen=True)
class RepetitionProtocol:
    warmup: int
    measured: int


@dataclass(frozen=True)
class RepetitionRun:
    phase: str
    iteration: int
    warmup: int
    measured: int

    @property
    def suffix(self) -> str:
        prefix = "warmup" if self.phase == "warmup" else "rep"
        return f"{prefix}{self.iteration:02d}"


def protocol_from_manifest(
    manifest: Mapping[str, Any],
    *,
    default_warmup: int = 0,
    default_measured: int = 1,
) -> RepetitionProtocol:
    repetitions = manifest.get("repetitions") or {}
    if not isinstance(repetitions, Mapping):
        repetitions = {}
    return RepetitionProtocol(
        warmup=max(0, int(repetitions.get("warmup", default_warmup))),
        measured=max(1, int(repetitions.get("measured", default_measured))),
    )


def iter_repetitions(protocol: RepetitionProtocol) -> Iterable[RepetitionRun]:
    for iteration in range(1, protocol.warmup + 1):
        yield RepetitionRun(
            phase="warmup",
            iteration=iteration,
            warmup=protocol.warmup,
            measured=protocol.measured,
        )
    for iteration in range(1, protocol.measured + 1):
        yield RepetitionRun(
            phase="measured",
            iteration=iteration,
            warmup=protocol.warmup,
            measured=protocol.measured,
        )


def attach_repetition(record: MutableMapping[str, Any], repetition: RepetitionRun) -> None:
    record["run_id"] = f"{record['run_id']}_{repetition.suffix}"
    record["measurement"] = {
        "phase": repetition.phase,
        "iteration": repetition.iteration,
        "warmup_repetitions": repetition.warmup,
        "measured_repetitions": repetition.measured,
    }
