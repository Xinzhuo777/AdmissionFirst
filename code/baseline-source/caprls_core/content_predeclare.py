"""Write predeclared expectations for content-boundary checks."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import yaml

from caprls_core.content_falsifier import sha256_plain

PREDECLARED_SCHEMA = "caprls-content-predeclaration-v1"

#: §5.3 T3 — declared arithmetic invariants.  **Diagnostic only, never
#: acceptance.**  E10's linear ladder over the 1e5 document relation at seed 52.
T3_ARITHMETIC_INVARIANTS = [
    OrderedDict(
        invariant="e10_document_authorized_ladder",
        statement="|sigma_Pi(document)| = 7000 at seed 52; the r_c ladder at "
        "doc_id <= 20000 / 50000 / 80000 over 100000 rows is linear: 1400 / 3500 / 5600",
        role="diagnostic_only",
        never="acceptance_criterion",
    ),
    OrderedDict(
        invariant="e10_share_acl_fanout",
        statement="share_acl yields exactly 2 distinct qualifying groups per document; "
        "Q6's pre-collapse branch bag is 14010 (own 10 + shared 14000) and the "
        "collapse equals 7000 = |auth|",
        role="diagnostic_only",
        never="acceptance_criterion",
    ),
    OrderedDict(
        invariant="e2_policy_set_cardinalities",
        statement="the frozen E2 policy-set cardinalities are 6 (doc_id <= 100) and "
        "68 (doc_id <= 1000); counts.authorized_rows = 6800 at seed 42",
        role="diagnostic_only",
        never="acceptance_criterion",
    ),
    OrderedDict(
        invariant="e3_authorized_rows_distinct_values",
        statement="the frozen E3 authorized_rows takes 5 distinct values over 33 cells "
        "({505662: 6, 252831: 6, 50566: 6, 15000: 10, 3000: 5}); 15000 covers ten "
        "cells because TPCH/cheap and TPCH/group_acl coincide in cardinality while "
        "being different predicates, so cardinality cannot identify a reference relation",
        role="diagnostic_only",
        never="acceptance_criterion",
    ),
]


class ContentPredeclarationError(RuntimeError):
    pass


def _sha256_bytes(path: Path) -> str:
    """Byte-exact file digest, identical to ``content_verify._sha256_file``."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_spec(spec_path: Path) -> Mapping[str, Any]:
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != "caprls-content-cells-v1":
        raise ContentPredeclarationError("content cell spec has the wrong schema")
    return data


def _reference_sql_for(root: Path, cell: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    """§9.3 — the reference SQL text and digest.

    Derivable offline for E3 (the predicate is a transcription of Python
    literals).  For E2/E10 it is derivable only after the context row is
    available (§6.3), so it is left ``null`` here and filled by the run.
    """

    if cell["family"] != "E3":
        return None
    from caprls_core import content_reference

    policies = content_reference.load_policy_manifest(root)
    payload = content_reference.build_reference(cell, policies, None)
    return {
        "reference_sql": payload["boundary_sql"],
        "reference_sql_digest": payload["boundary_sql_digest"],
        "reference_predicate_text": payload["reference_predicate_text"],
    }


def build_predeclaration(root: Path, spec_path: Optional[Path] = None) -> Dict[str, Any]:
    root = Path(root)
    spec_path = Path(spec_path) if spec_path else root / "specs" / "content_cells.yaml"
    spec = _load_spec(spec_path)

    cells: "OrderedDict[str, Any]" = OrderedDict()
    for cell in spec["cells"]:
        anchors = cell["anchors"]
        entry = OrderedDict()
        entry["cell_id"] = cell["cell_id"]
        entry["family"] = cell["family"]
        entry["reference_relation_id"] = cell["reference"]["reference_relation_id"]
        entry["comparison_id"] = cell["reference"]["comparison_id"]
        entry["boundary_kind"] = cell["boundary"]["kind"]
        entry["declared_columns"] = [
            OrderedDict(
                ordinal=c["ordinal"], name=c["name"], data_type=c["data_type"]
            )
            for c in cell["boundary"]["columns"]
        ]
        entry["r_c"] = cell["boundary"]["refinement"].get("r_c")
        entry["reference_r_c"] = cell["boundary"]["refinement"].get("reference_r_c")
        if cell["boundary"]["refinement"].get("exception"):
            entry["refinement_exception"] = cell["boundary"]["refinement"]["exception"]
        entry["expected_policy_cardinality"] = anchors["expected_policy_cardinality"]
        entry["anchor_kind"] = anchors["anchor_kind"]
        entry["anchor_source"] = anchors["anchor_source"]
        entry["companion_query"] = "SELECT count(*) FROM {} {} WHERE <Pi_c>".format(
            cell["boundary"]["reference_relation"], cell["boundary"]["reference_alias"]
        )
        entry["expected_vacuous"] = (
            True if cell["labels"]["vacuous_expected"] else False
        )
        entry["expected_vacuous_role"] = "observation_target_not_criterion"
        entry["frozen_result_row_count"] = anchors["frozen_result_row_count"]
        reference = _reference_sql_for(root, cell)
        if reference is not None:
            entry.update(reference)
            entry["reference_sql_availability"] = "derived_offline"
        else:
            entry["reference_sql"] = None
            entry["reference_sql_digest"] = None
            entry["reference_sql_availability"] = (
                "requires_context_row_from_public_synthetic_context"
            )
        if cell["family"] == "E2":
            entry["e2_no_frozen_cardinality_anchor"] = True
            entry["e2_disclosure"] = (
                "oracle_count is fail-fast and is never written to the raw record "
                "(e2_main.py:813-823, :861-864); the 8 E2 cells have no frozen "
                "cardinality anchor"
            )
        # Keyed by short_id: it is unique, filename-safe, and matches the
        # receipt filenames.  The full cell_id travels inside the entry.
        cells[cell["short_id"]] = entry

    anchored = sum(
        1 for e in cells.values() if e["anchor_kind"] == "upper_bound_on_boundary"
    )
    doc = OrderedDict()
    doc["schema"] = PREDECLARED_SCHEMA
    doc["written_at"] = datetime.now(timezone.utc).isoformat()
    doc["design_memo"] = "experiment specification"
    doc["role"] = "tamper_evidence_not_acceptance"
    doc["pass_criteria_are_elsewhere"] = (
        "candidate_digest == reference_digest AND actual_only_rows == 0 AND "
        "reference_only_rows == 0, plus the structural criteria"
    )
    doc["deviation_handling"] = (
        "a deviation sets expectation_deviation: true and triggers attribution "
        "it never causes automatic failure and never aborts the package"
    )
    doc["vacuity_handling"] = (
        "vacuity is an observed field; a non-vacuous Q5 routes the cell to refused "
        "+ investigation, never to package failure"
    )
    doc["spec_path"] = str(Path(spec_path).relative_to(root))
    doc["spec_digest"] = _sha256_bytes(Path(spec_path))
    doc["anchor_counts"] = OrderedDict(
        upper_bound_on_boundary=anchored,
        unanchored=len(cells) - anchored,
        note="no frozen quantity equals |A_c| for any of the 52 cells ",
    )
    doc["t3_arithmetic_invariants"] = T3_ARITHMETIC_INVARIANTS
    doc["spec_revision_rule"] = (
        "a run whose spec_digest differs from this pre-registration is emitted as "
        "status: pass_after_spec_revision and reported separately, permanently"
    )
    doc["cells"] = cells
    return doc


class _Dumper(yaml.SafeDumper):
    pass


def _represent_ordered(dumper, data):
    return dumper.represent_dict(data.items())


_Dumper.add_representer(OrderedDict, _represent_ordered)


def _represent_str(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _represent_str)


def write_predeclaration(
    root: Path, out_path: Path, spec_path: Optional[Path] = None
) -> Dict[str, Any]:
    doc = build_predeclaration(root, spec_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        raise ContentPredeclarationError(
            "refusing to overwrite an existing pre-registration: {} "
            "(the prior one is retained forever, the declared protocol)".format(out_path)
        )
    with out_path.open("w", encoding="utf-8") as handle:
        yaml.dump(
            doc, handle, Dumper=_Dumper, default_flow_style=False, sort_keys=False,
            allow_unicode=True, width=4096,
        )
    digest = _sha256_bytes(out_path)
    return {
        "path": str(out_path),
        "predeclared_digest": digest,
        "cells": len(doc["cells"]),
        "anchored": doc["anchor_counts"]["upper_bound_on_boundary"],
    }
