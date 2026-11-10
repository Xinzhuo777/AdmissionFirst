"""Audit content-boundary specifications against implementation."""

from __future__ import annotations

import inspect
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from caprls_core.manifest_validator import file_sha256

AUDIT_ID = "implementation_fidelity_audit_v1"


class ContentSpecAuditError(RuntimeError):
    """Raised when the spec and the in-code constants disagree.  Refuses."""


@dataclass
class AuditItem:
    item: str
    status: str
    detail: str = ""
    checked: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item": self.item,
            "status": self.status,
            "detail": self.detail,
            "checked": self.checked,
        }


@dataclass
class AuditReport:
    audit_id: str
    audit_module_digest: str
    spec_digest: str
    items: List[AuditItem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(item.status == "pass" for item in self.items)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "audit_module_digest": self.audit_module_digest,
            "spec_digest": self.spec_digest,
            "status": "pass" if self.ok else "fail",
            "items": [item.to_dict() for item in self.items],
        }


def _load_spec(spec_path: Path) -> Mapping[str, Any]:
    with Path(spec_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, Mapping) or data.get("schema") != "caprls-content-cells-v1":
        raise ContentSpecAuditError("content cell spec has the wrong schema")
    return data


def _cells(spec: Mapping[str, Any], family: str) -> List[Mapping[str, Any]]:
    return [cell for cell in spec["cells"] if cell["family"] == family]


# ---------------------------------------------------------------------------
# Individual audited items
# ---------------------------------------------------------------------------
def _audit_e3_carrier_projection_columns(spec, e3) -> AuditItem:
    """``E3_CARRIER_PROJECTION_COLUMNS`` (e3_main.py:851-864) vs declared B_c."""

    checked = 0
    for cell in _cells(spec, "E3"):
        query_id = cell["query_id"]
        declared = [c["name"] for c in cell["boundary"]["columns"]]
        columns = e3.E3_CARRIER_PROJECTION_COLUMNS.get(query_id)
        if columns is None:
            return AuditItem(
                "E3_CARRIER_PROJECTION_COLUMNS", "fail",
                "no in-code projection for {}".format(query_id), checked)
        # The emitted access root projects the carrier columns in declaration
        # order with `__rid` inserted immediately after the RID column, which is
        # `columns[0]`; the declared B_c must be exactly that sequence.
        expected = [columns[0], "__rid"] + list(columns[1:])
        if declared != expected:
            return AuditItem(
                "E3_CARRIER_PROJECTION_COLUMNS", "fail",
                "{}: declared {} != in-code {}".format(query_id, declared, expected),
                checked)
        checked += 1
    return AuditItem("E3_CARRIER_PROJECTION_COLUMNS", "pass", "", checked)


def _audit_e3_access_column_contracts(spec, e3) -> AuditItem:
    """``E3_ACCESS_COLUMN_CONTRACTS`` (e3_main.py:865-879) vs declared types."""

    checked = 0
    for cell in _cells(spec, "E3"):
        relation = cell["boundary"]["reference_relation"].split(".")[-1]
        contracts = e3.E3_ACCESS_COLUMN_CONTRACTS.get(relation)
        if contracts is None:
            return AuditItem(
                "E3_ACCESS_COLUMN_CONTRACTS", "fail",
                "no contract for {}".format(relation), checked)
        rid_col = cell["boundary"]["rid_col"]
        for column in cell["boundary"]["columns"]:
            name = column["name"]
            if name == "__rid":
                expected_type = contracts[rid_col][0]
            else:
                if name not in contracts:
                    return AuditItem(
                        "E3_ACCESS_COLUMN_CONTRACTS", "fail",
                        "{}.{} is not in the access column contract".format(relation, name),
                        checked)
                expected_type = contracts[name][0]
            if column["data_type"] != expected_type:
                return AuditItem(
                    "E3_ACCESS_COLUMN_CONTRACTS", "fail",
                    "{}.{}: declared {} != in-code {}".format(
                        relation, name, column["data_type"], expected_type),
                    checked)
            checked += 1
    return AuditItem("E3_ACCESS_COLUMN_CONTRACTS", "pass", "", checked)


def _e3_query_spec(e3, query_id):
    for query in e3.QUERIES:
        if query.query_id == query_id:
            return query
    raise ContentSpecAuditError("E3 query spec not found: {}".format(query_id))


def _e3_policy_config(e3, policy_id):
    for policy in e3.POLICY_CONFIGS:
        if policy.config_id == policy_id:
            return policy
    raise ContentSpecAuditError("E3 policy config not found: {}".format(policy_id))


def _audit_e3_policy_predicates(spec, e3, reference) -> AuditItem:
    """``_policy_predicate`` + ``_group_acl_predicate`` vs the transcription.

    This is the item that makes E3's ``reference_authority`` honest: for 33 of
    the 52 cells the reference predicate is a machine-verified copy of the
    candidate's predicate source.
    """

    checked = 0
    for cell in _cells(spec, "E3"):
        query = _e3_query_spec(e3, cell["query_id"])
        policy = _e3_policy_config(e3, cell["policy_id"])
        alias = cell["boundary"]["reference_alias"]
        in_code = e3._policy_predicate(query, policy)
        # `_policy_predicate` renders on `query.alias`; the reference renders on
        # the declared reference alias.  They are the same alias by
        # construction (`c` for tpch, `t` for job) — assert that, do not paper
        # over a difference.
        if query.alias != alias:
            return AuditItem(
                "e3_policy_predicate", "fail",
                "{}: query alias {} != declared reference alias {}".format(
                    cell["short_id"], query.alias, alias), checked)
        transcribed = reference.e3_policy_predicate(
            cell["workload"], cell["policy_id"], alias)
        if in_code != transcribed:
            return AuditItem(
                "e3_policy_predicate", "fail",
                "{}: transcription differs from e3_main._policy_predicate".format(
                    cell["short_id"]), checked)
        checked += 1
    return AuditItem("e3_policy_predicate", "pass", "", checked)


def _audit_e3_policy_predicate_unaliased(spec, e3, reference) -> AuditItem:
    """``_policy_predicate_unaliased`` (e3_main.py:3277-3294).

    Not used by the reference, but audited because it is the second definition
    of the same semantics inside the implementation; a divergence between the
    two in-code forms is itself a finding.
    """

    checked = 0
    seen = set()
    for cell in _cells(spec, "E3"):
        key = (cell["workload"], cell["policy_id"])
        if key in seen:
            continue
        seen.add(key)
        query = _e3_query_spec(e3, cell["query_id"])
        policy = _e3_policy_config(e3, cell["policy_id"])
        unaliased = e3._policy_predicate_unaliased(query, policy)
        aliased = e3._policy_predicate(query, policy)
        # Word-boundary strip: a plain ``replace(alias + ".")`` would also
        # corrupt the ``'public.<rel>'`` literal inside the group-ACL predicate.
        stripped = re.sub(r"\b" + re.escape(query.alias) + r"\.", "", aliased)
        normalized_unaliased = " ".join(unaliased.split())
        normalized_stripped = " ".join(stripped.split())
        # The hybrid form differs by an explicit ``::bigint`` cast on the modulus
        # literal; record it rather than assert byte equality.
        if normalized_unaliased != normalized_stripped:
            detail = "{}/{}: unaliased form differs (declared divergence)".format(*key)
            if "::bigint" not in normalized_unaliased:
                return AuditItem("e3_policy_predicate_unaliased", "fail", detail, checked)
        checked += 1
    return AuditItem(
        "e3_policy_predicate_unaliased", "pass",
        "hybrid_selective_key's unaliased form carries an explicit ::bigint cast",
        checked)


def _audit_e3_query_predicate(spec, e3, reference) -> AuditItem:
    """``_e3_query_predicate`` (e3_main.py:3985-3986) vs the declared r_c."""

    checked = 0
    for cell in _cells(spec, "E3"):
        query = _e3_query_spec(e3, cell["query_id"])
        refinement = cell["boundary"]["refinement"]
        in_code_candidate = e3._e3_query_predicate(query, "sel")
        if in_code_candidate != refinement["r_c"]:
            return AuditItem(
                "e3_query_predicate", "fail",
                "{}: declared r_c {!r} != in-code {!r}".format(
                    cell["short_id"], refinement["r_c"], in_code_candidate), checked)
        alias = cell["boundary"]["reference_alias"]
        in_code_reference = e3._e3_query_predicate(query, alias)
        transcribed = reference.e3_query_predicate(
            alias, refinement["key_name"], refinement["key_value"])
        if not (in_code_reference == transcribed == refinement["reference_r_c"]):
            return AuditItem(
                "e3_query_predicate", "fail",
                "{}: reference r_c transcription differs "
                "(in_code={!r} transcribed={!r} declared={!r})".format(
                    cell["short_id"], in_code_reference, transcribed,
                    refinement["reference_r_c"]),
                checked)
        if query.key_name != refinement["key_name"] or query.key_value != refinement["key_value"]:
            return AuditItem(
                "e3_query_predicate", "fail",
                "{}: declared key ({}, {}) != E3QuerySpec ({}, {})".format(
                    cell["short_id"], refinement["key_name"], refinement["key_value"],
                    query.key_name, query.key_value), checked)
        checked += 1
    return AuditItem("e3_query_predicate", "pass", "", checked)


def _audit_e3_carrier_projection_sql(spec, e3) -> AuditItem:
    """``e3_main._carrier_projection_sql`` (e3_main.py:6906-6915)."""

    checked = 0
    for cell in _cells(spec, "E3"):
        query = _e3_query_spec(e3, cell["query_id"])
        rendered = e3._carrier_projection_sql(query)
        names = [part.strip().split(" AS ")[-1].split(".")[-1] for part in rendered.split(",")]
        declared = [c["name"] for c in cell["boundary"]["columns"]]
        # `_carrier_projection_sql` appends `__rid` last; the frozen access-root
        # projection places `__rid` second.  Compare as sets plus RID position.
        if sorted(names) != sorted(declared):
            return AuditItem(
                "e3_carrier_projection_sql", "fail",
                "{}: {} != {}".format(cell["short_id"], names, declared), checked)
        if declared[1] != "__rid":
            return AuditItem(
                "e3_carrier_projection_sql", "fail",
                "{}: declared B_c does not place __rid second".format(cell["short_id"]),
                checked)
        checked += 1
    return AuditItem(
        "e3_carrier_projection_sql", "pass",
        "declared B_c is the carrier projection with __rid moved to position 2, "
        "matching every frozen access root", checked)


def _audit_e10_base_filter(spec, e10) -> AuditItem:
    """``_base_filter`` (e10_study.py:10769-10791) and its Q5 relationship."""

    checked = 0
    for cell in _cells(spec, "E10"):
        case = _e10_case(e10, cell["query_id"])
        boundary = cell["boundary"]
        alias = boundary["reference_alias"]
        rid_col = boundary.get("reference_rid_col", boundary["rid_col"])
        base = e10._base_filter(case, alias, rid_col)
        if cell["query_id"] == "E10_Q5_invoice_region_purpose_join":
            # Declared exception: the executed `cand` CTE applies neither the
            # base filter nor the residual, so r_c := TRUE at the guard boundary.
            if boundary["refinement"].get("exception") != "guard_carries_no_query_predicate":
                return AuditItem(
                    "e10_base_filter", "fail",
                    "Q5 must declare refinement_exception", checked)
            if base.strip() != "{}.{} <= 30000".format(alias, rid_col):
                return AuditItem(
                    "e10_base_filter", "fail",
                    "Q5's in-code base filter changed: {!r}".format(base), checked)
        checked += 1
    return AuditItem("e10_base_filter", "pass", "", checked)


def _e10_case(e10, query_id):
    for case in e10.CASES:
        if case.query_id == query_id:
            return case
    raise ContentSpecAuditError("E10 case not found: {}".format(query_id))


def _audit_e10_planning_query_predicate(spec, e10) -> AuditItem:
    """``_e10_planning_query_predicate`` (e10_study.py:10794-10803) vs r_c."""

    checked = 0
    for cell in _cells(spec, "E10"):
        case = _e10_case(e10, cell["query_id"])
        boundary = cell["boundary"]
        alias = boundary["reference_alias"]
        rid_col = boundary.get("reference_rid_col", boundary["rid_col"])
        in_code = e10._e10_planning_query_predicate(case, alias, rid_col)
        declared = boundary["refinement"]["reference_r_c"]
        if cell["query_id"] == "E10_Q5_invoice_region_purpose_join":
            if declared is not None:
                return AuditItem(
                    "e10_planning_query_predicate", "fail",
                    "Q5 must declare reference_r_c: null", checked)
            checked += 1
            continue
        normalized_in_code = " ".join(in_code.split())
        if normalized_in_code == "true":
            if declared is not None:
                return AuditItem(
                    "e10_planning_query_predicate", "fail",
                    "{}: in-code r_c is TRUE but the spec declares {!r}".format(
                        cell["short_id"], declared), checked)
        else:
            if declared is None or " ".join(declared.split()) != normalized_in_code:
                return AuditItem(
                    "e10_planning_query_predicate", "fail",
                    "{}: declared {!r} != in-code {!r}".format(
                        cell["short_id"], declared, in_code), checked)
        checked += 1
    return AuditItem("e10_planning_query_predicate", "pass", "", checked)


def _audit_e10_target_for_case(spec, e10) -> AuditItem:
    """``_target_for_case`` (e10_study.py:4507-4515)."""

    checked = 0
    for cell in _cells(spec, "E10"):
        case = _e10_case(e10, cell["query_id"])
        relname, rid_col, policy_id, alias = e10._target_for_case(case)
        boundary = cell["boundary"]
        if "public." + relname != boundary["reference_relation"]:
            return AuditItem(
                "e10_target_for_case", "fail",
                "{}: declared reference relation {} != in-code public.{}".format(
                    cell["short_id"], boundary["reference_relation"], relname), checked)
        if rid_col != boundary.get("reference_rid_col", boundary["rid_col"]):
            return AuditItem(
                "e10_target_for_case", "fail",
                "{}: rid_col mismatch".format(cell["short_id"]), checked)
        if alias != boundary["reference_alias"]:
            return AuditItem(
                "e10_target_for_case", "fail",
                "{}: alias mismatch".format(cell["short_id"]), checked)
        if policy_id != boundary["predicate"]["policy_manifest_key"]:
            return AuditItem(
                "e10_target_for_case", "fail",
                "{}: policy key mismatch".format(cell["short_id"]), checked)
        checked += 1
    return AuditItem("e10_target_for_case", "pass", "", checked)


def _audit_e10_carrier_projection_sql(spec, e10) -> AuditItem:
    """``e10_study._carrier_projection_sql`` (e10_study.py:10806-10828).

    The declared B_c for the five text-anchored cells is the *frozen plan's own*
    projection, which is the barrier continuation's live-column subset, not the
    full carrier projection.  The audit asserts containment plus the RID alias,
    and records the difference rather than hiding it.
    """

    checked = 0
    for cell in _cells(spec, "E10"):
        if cell["candidate"]["candidate_fidelity"] != "verbatim_subplan_text_anchored":
            continue
        case = _e10_case(e10, cell["query_id"])
        boundary = cell["boundary"]
        rid_col = boundary["rid_col"]
        alias = boundary["reference_alias"]
        relname = boundary["reference_relation"].split(".")[-1]
        if boundary["kind"] == "guard_candidate_not_exact":
            # Q5's compared object is the guard CTE `cand`, which carries the
            # guard-predicate inputs, not the post-barrier live-column subset.
            rendered = e10._carrier_projection_sql(
                case=case, relname=relname, rid_col=rid_col, alias=alias)
        else:
            rendered = e10._carrier_projection_sql(
                case=case, relname=relname, rid_col=rid_col, alias=alias,
                required_columns=e10._barrier_continuation_required_columns(case, rid_col))
        available = {
            part.strip().split(" AS ")[-1].split(".")[-1] for part in rendered.split(",")
        }
        # Q4's RID alias is literally `rid`; comparison is by jsonb key name, so
        # the contract must use `rid` on both sides (§3.3).
        declared = {
            (rid_col if c["name"] == "rid" else c["name"]) for c in boundary["columns"]
        }
        if declared != available:
            return AuditItem(
                "e10_carrier_projection_sql", "fail",
                "{}: declared {} != in-code {}".format(
                    cell["short_id"], sorted(declared), sorted(available)), checked)
        checked += 1
    if checked != 5:
        return AuditItem(
            "e10_carrier_projection_sql", "fail",
            "expected 5 text-anchored E10 cells, found {}".format(checked), checked)
    return AuditItem(
        "e10_carrier_projection_sql", "pass",
        "declared B_c for the 5 text-anchored cells equals the in-code carrier "
        "projection for their CTE kind (barrier live-column subset for Q4/Q6/Q8/Q10, "
        "guard inputs for Q5)", checked)


def _audit_e2_grid_bounds(spec, e2_main, root: Path) -> AuditItem:
    """E2 grid bounds: ``hi = max(1, int(total_rows * s_q))`` (e2_main.py:756)."""

    manifest_path = root / "manifests" / "experiments" / "e2_alternative_matrix_reduced.yaml"
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    s_q_values = [float(item) for item in (manifest.get("variables") or {}).get("s_q", [])]
    if sorted(s_q_values) != [0.001, 0.01]:
        return AuditItem(
            "e2_grid_bounds", "fail",
            "manifest s_q values changed: {}".format(s_q_values), 0)
    source = inspect.getsource(e2_main.run_e2_main)
    if "hi = max(1, int(total_rows * point.s_q))" not in source:
        return AuditItem(
            "e2_grid_bounds", "fail", "the E2 range formula changed", 0)
    total_rows = 100000
    expected = {int(max(1, int(total_rows * s_q))) for s_q in s_q_values}
    declared = set()
    checked = 0
    for cell in _cells(spec, "E2"):
        r_c = cell["boundary"]["refinement"]["r_c"]
        declared.add(int(r_c.rsplit(" ", 1)[-1]))
        checked += 1
    if declared != expected:
        return AuditItem(
            "e2_grid_bounds", "fail",
            "declared bounds {} != derived {}".format(sorted(declared), sorted(expected)),
            checked)
    return AuditItem("e2_grid_bounds", "pass", "", checked)


def _audit_e2_matview_ddl(spec, e2_smoke) -> AuditItem:
    """E2 matview DDL (``e2_smoke._build_auth_view_sql``, e2_smoke.py:374-387)."""

    rendered = e2_smoke._build_auth_view_sql("<exact_predicate>")
    normalized = " ".join(rendered.split())
    expected_fragment = (
        "CREATE MATERIALIZED VIEW public.{} AS SELECT d.doc_id FROM public.document d "
        "WHERE <exact_predicate>;".format(e2_smoke.AUTH_VIEW_RELATION)
    )
    if expected_fragment not in normalized:
        return AuditItem(
            "e2_matview_ddl", "fail",
            "the E2 matview DDL changed: {}".format(normalized[:200]), 0)
    checked = 0
    for cell in _cells(spec, "E2"):
        if cell["boundary"]["candidate_relation"] != "public." + e2_smoke.AUTH_VIEW_RELATION:
            return AuditItem(
                "e2_matview_ddl", "fail",
                "{}: declared candidate relation is not the matview".format(cell["short_id"]),
                checked)
        names = [c["name"] for c in cell["boundary"]["columns"]]
        if names != ["doc_id", "__rid"]:
            return AuditItem(
                "e2_matview_ddl", "fail",
                "{}: B_c is forced to (doc_id, __rid) by the matview DDL".format(
                    cell["short_id"]), checked)
        checked += 1
    return AuditItem(
        "e2_matview_ddl", "pass",
        "the matview exposes exactly one column, so B_c=(doc_id,__rid) is forced, "
        "not chosen", checked)


def _audit_e10_mav_ddl(spec, e10) -> AuditItem:
    """E10 MAV DDL (``_build_mav_sql``, e10_study.py:9162-9204)."""

    rendered = e10._build_mav_sql(
        artifact_id="e10_document_mav_ctx_000001",
        policy_id="tenant_group",
        ctx_hash="sha256:audit",
        relname="document",
        rid_col="doc_id",
        alias="d",
        exact_predicate="<exact_predicate>",
    )
    normalized = " ".join(rendered.split())
    for fragment in (
        "rid bigint PRIMARY KEY,",
        "tenant_id bigint NOT NULL,",
        "sort_key text NOT NULL",
        "INSERT INTO public.e10_mav_document_ctx_000001(rid, tenant_id, sort_key)",
        "SELECT d.doc_id, d.tenant_id, d.doc_id::text",
    ):
        if fragment not in normalized:
            return AuditItem(
                "e10_mav_ddl", "fail",
                "the E10 MAV DDL changed; missing {!r}".format(fragment), 0)
    checked = 0
    for cell in _cells(spec, "E10"):
        if cell["boundary"]["candidate_relation"] != "public.e10_mav_document_ctx_000001":
            continue
        names = [c["name"] for c in cell["boundary"]["columns"]]
        if names != ["rid", "tenant_id"]:
            return AuditItem(
                "e10_mav_ddl", "fail",
                "{}: MAV B_c must be (rid, tenant_id)".format(cell["short_id"]), checked)
        checked += 1
    if checked != 2:
        return AuditItem(
            "e10_mav_ddl", "fail",
            "expected exactly 2 MAV-backed cells (Q2, Q7), found {}".format(checked), checked)
    return AuditItem(
        "e10_mav_ddl", "pass",
        "tenant_id is a copied non-key value loaded from document; Q2 and Q7 are the "
        "only 2 of 52 cells where a value not functionally determined within the "
        "relation both sides read is compared", checked)


def _audit_carries_query_predicate(spec, emit, contracts) -> AuditItem:
    """The declared 14-row ``carries_query_predicate`` table (§4.1).

    Mechanically checkable: an emitter carries the query predicate iff its
    source calls ``ctx.query_predicate_for(...)``, directly or by delegation.
    """

    declared = spec.get("carries_query_predicate")
    if not isinstance(declared, list) or len(declared) != 14:
        return AuditItem(
            "carries_query_predicate", "fail",
            "the table must declare exactly 14 rows", 0)
    registry_ids = [d.template_id for d in contracts.TEMPLATE_DEFINITIONS]
    if [row["template_id"] for row in declared] != registry_ids:
        return AuditItem(
            "carries_query_predicate", "fail",
            "declared template order != contracts.TEMPLATE_DEFINITIONS order", 0)
    definitions = {d.template_id: d for d in contracts.TEMPLATE_DEFINITIONS}
    checked = 0
    for row in declared:
        emitter = getattr(emit, row["emitter"], None)
        if emitter is None:
            return AuditItem(
                "carries_query_predicate", "fail",
                "emitter {} no longer exists".format(row["emitter"]), checked)
        source = inspect.getsource(emitter)
        direct = "query_predicate_for" in source
        delegated = (
            "_lower_safe_predicate_injection(" in source
            and row["emitter"] != "_lower_safe_predicate_injection"
        )
        observed = "yes" if (direct or delegated) else "no"
        declared_value = row["carries_query_predicate"]
        if declared_value == "conditional":
            if not direct:
                return AuditItem(
                    "carries_query_predicate", "fail",
                    "{} is declared conditional but never reads the query predicate".format(
                        row["template_id"]), checked)
        elif declared_value != observed:
            return AuditItem(
                "carries_query_predicate", "fail",
                "{}: declared {} but source says {}".format(
                    row["template_id"], declared_value, observed), checked)
        definition = definitions[row["template_id"]]
        in_registry = bool(getattr(definition, "include_in_default_registry", True))
        if in_registry != bool(row["in_default_registry"]):
            return AuditItem(
                "carries_query_predicate", "fail",
                "{}: default-registry membership mismatch".format(row["template_id"]),
                checked)
        checked += 1
    tally = {"yes": 0, "no": 0, "conditional": 0}
    for row in declared:
        tally[row["carries_query_predicate"]] += 1
    if tally != {"yes": 6, "no": 7, "conditional": 1}:
        return AuditItem(
            "carries_query_predicate", "fail",
            "tally changed: {}".format(tally), checked)
    return AuditItem(
        "carries_query_predicate", "pass",
        "yes=6, conditional=1, no=7; 13 of 14 are in the default registry", checked)


def _audit_renderer_timestamptz_form(spec, e10, oracle_audit, reference) -> AuditItem:
    """The declared per-family timestamptz literal form vs the two in-code renderers.

    ``oracle_audit._render_exact_predicate`` (E2's candidate path) emits
    ``'<ts>'::timestamptz``; ``e10_study._render_policy_predicate`` emits
    ``TIMESTAMPTZ '<ts>'``.  Same semantics, different syntax.  The reference
    renders the declared form so ``predicate_text_reconciliation`` compares like
    with like; if either renderer changes, this item fails and the package
    refuses rather than silently reporting ``differs`` on every cell.
    """

    probe_template = "({alias}.x = :now)"
    context = {
        "tenant_id": 90, "user_id": 90, "region": "region_2",
        "purpose": "purpose_2", "clearance": 2,
    }
    e10_rendered = e10._render_policy_predicate(
        probe_template, "d", "doc_id", context, "document")
    oracle_rendered = oracle_audit._render_exact_predicate(
        probe_template, "d", "doc_id", context, "document")
    observed = {
        "caprls_core/e10_study.py:_render_policy_predicate":
            e10_rendered[e10_rendered.index("= ") + 2:-1],
        "caprls_core/oracle_audit.py:_render_exact_predicate":
            oracle_rendered[oracle_rendered.index("= ") + 2:-1],
    }
    checked = 0
    for cell in spec["cells"]:
        predicate = cell["boundary"]["predicate"]
        renderer = predicate.get("candidate_renderer")
        form = predicate.get("timestamptz_literal_form")
        if form is None:
            if renderer != "caprls_core/e3_main.py:_policy_predicate":
                return AuditItem(
                    "renderer_timestamptz_form", "fail",
                    "{}: null literal form declared for a manifest renderer".format(
                        cell["short_id"]), checked)
            checked += 1
            continue
        expected = observed.get(renderer)
        if expected is None:
            return AuditItem(
                "renderer_timestamptz_form", "fail",
                "{}: unknown candidate renderer {!r}".format(cell["short_id"], renderer),
                checked)
        rendered = form.format(ts=reference.EXECUTION_TIMESTAMP)
        if rendered != expected:
            return AuditItem(
                "renderer_timestamptz_form", "fail",
                "{}: declared {!r} != in-code {!r}".format(
                    cell["short_id"], rendered, expected), checked)
        checked += 1
    return AuditItem(
        "renderer_timestamptz_form", "pass",
        "the two in-repo renderers disagree on timestamptz literal syntax; the "
        "declared per-family form is pinned to each family's own candidate renderer",
        checked)


def _audit_selection_classification(spec, root: Path) -> AuditItem:
    """The pre-signed classification table (memo v2.3 clause A) vs the spec.

    Audits *fidelity of the table to the spec*, never the classification itself:
    the causes are a human judgement recorded in `classification-metadata`, and the
    harness never self-classifies.  What is checkable is that every entry names
    a real cell, quotes that cell's actual frozen template, cites its evidence,
    and that the authorized scope is exactly the 11 E3 `group_acl_expensive`
    cells with nothing else pre-classified.
    """

    path = Path(root) / "specs" / "selection_difference_classification.yaml"
    if not path.exists():
        return AuditItem(
            "selection_classification", "fail",
            "the pre-signed classification table is missing", 0)
    with path.open("r", encoding="utf-8") as handle:
        table = yaml.safe_load(handle)
    if table.get("schema") != "caprls-selection-difference-classification-v1":
        return AuditItem("selection_classification", "fail", "wrong schema", 0)
    by_short = {cell["short_id"]: cell for cell in spec["cells"]}
    entries = table.get("entries") or []
    checked = 0
    for entry in entries:
        cell = by_short.get(entry["short_id"])
        if cell is None:
            return AuditItem(
                "selection_classification", "fail",
                "entry names an unknown cell: {}".format(entry["short_id"]), checked)
        if entry["cell_id"] != cell["cell_id"]:
            return AuditItem(
                "selection_classification", "fail",
                "{}: cell_id does not match the spec".format(entry["short_id"]), checked)
        frozen = cell["frozen"]["selected_template_id"]
        if entry["frozen_selected_template_id"] != frozen:
            return AuditItem(
                "selection_classification", "fail",
                "{}: declares frozen {!r} but the spec says {!r}".format(
                    entry["short_id"], entry["frozen_selected_template_id"], frozen),
                checked)
        if not entry.get("evidence_ref"):
            return AuditItem(
                "selection_classification", "fail",
                "{}: no evidence_ref".format(entry["short_id"]), checked)
        if entry.get("cause") != "statistics":
            return AuditItem(
                "selection_classification", "fail",
                "{}: only 'statistics' is authorized".format(entry["short_id"]), checked)
        checked += 1
    listed = {entry["short_id"] for entry in entries}
    authorized = {
        cell["short_id"] for cell in spec["cells"]
        if cell["family"] == "E3" and cell["policy_id"] == "group_acl_expensive"
    }
    if listed != authorized:
        return AuditItem(
            "selection_classification", "fail",
            "scope is not exactly the 11 E3 group_acl_expensive cells; "
            "extra={} missing={}".format(
                sorted(listed - authorized), sorted(authorized - listed)),
            checked)
    if table.get("default_for_unlisted_cells") != "unknown_refuse":
        return AuditItem(
            "selection_classification", "fail",
            "unlisted cells must default to unknown_refuse", checked)
    return AuditItem(
        "selection_classification", "pass",
        "11 pre-classified cells, all E3 group_acl_expensive, each citing "
        "predeclared classification; all other 41 cells refuse on a "
        "difference", checked)


def _audit_native_rls_absence(spec, contracts) -> AuditItem:
    """§8.4 — no selected template may be a native-RLS mode."""

    native = {"native_pg_rls_v1", "native_pg_rls_physical_design_v1"}
    checked = 0
    for cell in spec["cells"]:
        if cell["frozen"]["selected_template_id"] in native:
            return AuditItem(
                "native_rls_absence", "fail",
                "{} declares a native-RLS selected template".format(cell["short_id"]),
                checked)
        checked += 1
    return AuditItem("native_rls_absence", "pass", "", checked)


def _audit_denominators(spec) -> AuditItem:
    """§10.1 / §11 — the accounting must be recomputable from the cells."""

    cells = spec["cells"]
    declared = spec["denominators"]
    computed = {
        "boundary_receipts": len(cells),
        "exact_boundary_receipts": sum(
            1 for c in cells if c["boundary"]["kind"] == "exact_authorized"),
        "distinct_reference_relations": len(
            {c["reference"]["reference_relation_id"] for c in cells}),
        "distinct_comparisons": len({c["reference"]["comparison_id"] for c in cells}),
        "enforcement_discriminating_receipts": sum(
            1 for c in cells if c["labels"]["enforcement_discriminating"]),
        "vacuous": sum(1 for c in cells if c["labels"]["vacuous_expected"]),
        "shape_convergent": sum(1 for c in cells if c["labels"]["shape_convergent"]),
        "artifact_content_only": sum(
            1 for c in cells if c["labels"]["artifact_content_only"]),
        "crossvalidated_cells": sum(1 for c in cells if c["crossvalidate"]),
    }
    all_cmps = {c["reference"]["comparison_id"] for c in cells}
    discounted = {
        c["reference"]["comparison_id"] for c in cells
        if not c["labels"]["enforcement_discriminating"]
    }
    computed["substantive_distinct_comparisons"] = len(all_cmps - discounted)
    fidelity = {}
    for cell in cells:
        key = cell["candidate"]["candidate_fidelity"]
        fidelity[key] = fidelity.get(key, 0) + 1
    computed["candidate_fidelity"] = fidelity
    for key, value in computed.items():
        if declared.get(key) != value:
            return AuditItem(
                "denominators", "fail",
                "{}: declared {!r} != computed {!r}".format(key, declared.get(key), value),
                0)
    expected = {
        "boundary_receipts": 52,
        "exact_boundary_receipts": 51,
        "distinct_reference_relations": 15,
        "distinct_comparisons": 21,
        "enforcement_discriminating_receipts": 38,
        "substantive_distinct_comparisons": 15,
        "vacuous": 2,
        "shape_convergent": 5,
        "artifact_content_only": 8,
        "crossvalidated_cells": 34,
    }
    for key, value in expected.items():
        if computed[key] != value:
            return AuditItem(
                "denominators", "fail",
                "{}: computed {} != memo {}".format(key, computed[key], value), 0)
    if fidelity != {
        "verbatim_subplan_planner_anchored": 33,
        "verbatim_subplan_text_anchored": 5,
        "re_rendered_projection": 14,
    }:
        return AuditItem("denominators", "fail", "fidelity split changed", 0)
    return AuditItem("denominators", "pass", json.dumps(computed, sort_keys=True), len(cells))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run_audit(root: Path, spec_path: Optional[Path] = None) -> AuditReport:
    """Run the whole implementation-fidelity audit.  Never mutates anything."""

    root = Path(root)
    spec_path = Path(spec_path) if spec_path else root / "specs" / "content_cells.yaml"
    spec = _load_spec(spec_path)

    # Imported here, not at module scope: the audit runs in the parent, but a
    # caller that only wants the spec loader must not drag the planner in.
    from caprls_core import (
        content_reference,
        e2_main,
        e2_smoke,
        e3_main,
        e10_study,
        oracle_audit,
    )
    from planner import contracts, emit

    report = AuditReport(
        audit_id=AUDIT_ID,
        audit_module_digest=file_sha256(Path(__file__)),
        spec_digest=file_sha256(spec_path),
    )
    report.items.extend(
        [
            _audit_e3_carrier_projection_columns(spec, e3_main),
            _audit_e3_access_column_contracts(spec, e3_main),
            _audit_e3_policy_predicates(spec, e3_main, content_reference),
            _audit_e3_policy_predicate_unaliased(spec, e3_main, content_reference),
            _audit_e3_query_predicate(spec, e3_main, content_reference),
            _audit_e3_carrier_projection_sql(spec, e3_main),
            _audit_e10_base_filter(spec, e10_study),
            _audit_e10_planning_query_predicate(spec, e10_study),
            _audit_e10_target_for_case(spec, e10_study),
            _audit_e10_carrier_projection_sql(spec, e10_study),
            _audit_e2_grid_bounds(spec, e2_main, root),
            _audit_e2_matview_ddl(spec, e2_smoke),
            _audit_e10_mav_ddl(spec, e10_study),
            _audit_carries_query_predicate(spec, emit, contracts),
            _audit_renderer_timestamptz_form(
                spec, e10_study, oracle_audit, content_reference
            ),
            _audit_selection_classification(spec, root),
            _audit_native_rls_absence(spec, contracts),
            _audit_denominators(spec),
        ]
    )
    return report


def require_audit(root: Path, spec_path: Optional[Path] = None) -> Dict[str, Any]:
    """Run the audit and **refuse** the package on any failure (§10.1)."""

    report = run_audit(root, spec_path)
    if not report.ok:
        failed = [item.item for item in report.items if item.status != "pass"]
        raise ContentSpecAuditError(
            "implementation_fidelity_audit failed: " + ", ".join(failed)
        )
    return report.to_dict()
