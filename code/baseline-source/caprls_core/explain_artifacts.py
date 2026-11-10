"""Static-verifier EXPLAIN artifact helpers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any, Optional


_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_component(value: str) -> str:
    safe = _SAFE_COMPONENT_RE.sub("_", value).strip("._")
    return safe or "explain"


def write_explain_artifact(
    output_dir: Path,
    *,
    run_id: str,
    template_id: str,
    explain_json: Any,
) -> str:
    relative = Path("explain") / (
        f"{_safe_component(run_id)}_{_safe_component(template_id)}.explain.json"
    )
    target = output_dir / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(explain_json, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return relative.as_posix()


def attach_static_verifier_explain(
    record: MutableMapping[str, Any],
    output_dir: Path,
    explain_json: Any,
) -> Optional[str]:
    if explain_json is None:
        return None
    static_verifier = record.get("static_verifier")
    if not isinstance(static_verifier, MutableMapping):
        return None
    template = record.get("template")
    template_id = "unknown_template"
    if isinstance(template, Mapping):
        template_id = str(template.get("template_id") or template_id)
    relative_path = write_explain_artifact(
        output_dir,
        run_id=str(record.get("run_id") or "unknown_run"),
        template_id=template_id,
        explain_json=explain_json,
    )
    static_verifier["explain_path"] = relative_path
    return relative_path
