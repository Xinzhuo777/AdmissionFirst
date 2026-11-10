"""Local proof provenance and data bindings for continuation-scoped targets.

The descriptor contains serializable values only. Its local registration holds
the checked necessity source/proof and upstream Gamma; copied JSON or a copied
dataclass is not proof provenance. A trusted adapter must observe the supplied
schema and establish safe ordinary reads before issuing the corresponding
Gamma fact. This module does not attest a database or authorize execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any, Mapping
import weakref

from .contracts import GammaFact, GammaSnapshot, PolicyAccessTarget
from .continuation_necessity import (
    BoundNecessitySource, NecessityEvidence, NecessityError,
    require_necessity_evidence,
)
from .execution import SemanticContinuationScope


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RELATION = re.compile(r"[a-z_][a-z_0-9]{0,62}\Z")
_REGISTERED: dict[int, tuple[weakref.ReferenceType, BoundNecessitySource,
                            NecessityEvidence, GammaSnapshot, str]] = {}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode()).hexdigest()


def _gamma_payload(gamma: GammaSnapshot) -> dict[str, Any]:
    if type(gamma) is not GammaSnapshot or type(gamma.snapshot_id) is not str:
        raise NecessityError("refinement needs an exact Gamma snapshot")
    facts = []
    for fact in gamma.facts:
        if type(fact) is not GammaFact:
            raise NecessityError("refinement Gamma contains a nonexact fact")
        payload = {key:getattr(fact,key) for key in (
            "fact_id","kind","subject_digest","verdict","validator_version",
            "snapshot_id","evidence_digest","dynamic")}
        if (any(type(value) is not str for key,value in payload.items() if key != "dynamic")
            or type(fact.dynamic) is not bool):
            raise NecessityError("refinement Gamma fact has unsupported scalar types")
        fact.__post_init__()
        facts.append(payload)
    if len({fact["fact_id"] for fact in facts}) != len(facts):
        raise NecessityError("refinement Gamma has duplicate fact identities")
    fresh = GammaSnapshot(gamma.snapshot_id, tuple(gamma.facts)).digest
    if gamma.digest != fresh:
        raise NecessityError("refinement Gamma has a stale cached digest")
    return {"snapshot_id": gamma.snapshot_id,
            "facts": sorted(facts,key=lambda value:value["fact_id"]),
            "legacy_digest": fresh}


def _schema_requirements(report: Mapping[str, Any]) -> dict[tuple[str,str], dict[str,Any]]:
    binding = report["source_binding"]["bindings"]
    physical = binding["target"]["relation"]
    if type(physical) is not str or _RELATION.fullmatch(physical) is None:
        raise NecessityError("refinement protected relation is outside public finite syntax")
    required = {}
    for alias, relation in report["required_schema_assumptions"].items():
        name = (physical if relation["role"] == "protected_input"
                else relation["relation"].removeprefix("public."))
        if not _RELATION.fullmatch(name):
            raise NecessityError("refinement ordinary relation is outside finite syntax")
        for column in relation["columns"]:
            key = alias, column["name"]
            if key in required:
                raise NecessityError("refinement schema has duplicate source columns")
            required[key] = {**column,"relation_name":name}
    return required


def _validate_schema_claims(report: Mapping[str,Any], claims: Any) -> list[dict[str,Any]]:
    required = _schema_requirements(report)
    if type(claims) not in (list,tuple):
        raise NecessityError("refinement schema requires explicit catalog rows")
    keys = {"alias","relation_name","relation_oid","column_name","attnum",
            "type_namespace","type_name","type_oid","type_kind","typmod",
            "collation","collation_oid","collation_deterministic","generated","nullable"}
    seen = {}
    for row in claims:
        if type(row) is not dict or set(row) != keys:
            raise NecessityError("refinement catalog column shape mismatch")
        for key in ("alias","relation_name","column_name","type_namespace","type_name","type_kind","generated"):
            if type(row[key]) is not str:
                raise NecessityError("refinement catalog column names must be exact strings")
        pair = row["alias"],row["column_name"]
        expected = required.get(pair)
        if expected is None or pair in seen:
            raise NecessityError("refinement catalog column inventory mismatch")
        for key in ("relation_oid","attnum","type_oid"):
            if type(row[key]) is not int or row[key] <= 0:
                raise NecessityError("refinement catalog column identity is invalid")
        if (type(row["typmod"]) is not int or type(row["collation_oid"]) is not int
            or type(row["nullable"]) is not bool or row["generated"] != ""
            or row["type_kind"] != "b"):
            raise NecessityError("refinement catalog column semantics are unsupported")
        if any(row[key] != expected[key] for key in
               ("relation_name","type_namespace","type_name","typmod","collation")):
            raise NecessityError("refinement catalog column differs from proof assumptions")
        if expected["collation"] is None:
            if row["collation_oid"] != 0 or row["collation_deterministic"] is not None:
                raise NecessityError("refinement noncollatable column has a collation")
        elif (row["collation_oid"] <= 0 or row["collation_deterministic"] is not True):
            raise NecessityError("refinement requires the recorded deterministic builtin collation")
        seen[pair] = dict(row)
    if set(seen) != set(required):
        raise NecessityError("refinement catalog observation is incomplete")
    # Repeated aliases for one physical input must describe that same object.
    physical_rows = {}
    relation_oids = {}
    for row in seen.values():
        old_oid = relation_oids.setdefault(row["relation_name"],row["relation_oid"])
        if old_oid != row["relation_oid"]:
            raise NecessityError("refinement physical relation identity is inconsistent")
        physical = row["relation_name"],row["column_name"]
        payload = {key:value for key,value in row.items() if key != "alias"}
        if physical in physical_rows and physical_rows[physical] != payload:
            raise NecessityError("refinement physical column claims are inconsistent")
        physical_rows[physical] = payload
    return [seen[key] for key in sorted(seen)]


@dataclass(frozen=True)
class ContinuationRefinement:
    report_json: str
    schema_claims_json: str
    base_gamma_json: str
    result_contract_digest: str

    def to_dict(self) -> dict[str,Any]:
        if (any(type(value) is not str for value in
                (self.report_json,self.schema_claims_json,self.base_gamma_json,self.result_contract_digest))
            or _DIGEST.fullmatch(self.result_contract_digest) is None):
            raise NecessityError("refinement descriptor contains malformed identities")
        return {"schema":"caprls_continuation_refinement_v1",
                "necessity":json.loads(self.report_json),
                "schema_claims":json.loads(self.schema_claims_json),
                "base_gamma":json.loads(self.base_gamma_json),
                "result_contract_digest":self.result_contract_digest}

    @property
    def digest(self) -> str:
        return _hash(self.to_dict())

    @property
    def predicate_sql(self) -> str:
        report = json.loads(self.report_json)
        return "("+report["source_binding"]["bindings"]["q_predicate_sql"]+") AND ("+report["predicate_sql"]+")"

    @property
    def subject_digest(self) -> str:
        return _hash({"kind":"continuation_necessity","descriptor_digest":self.digest})

    def execution_scope(self) -> SemanticContinuationScope:
        report = require_continuation_refinement(self)["necessity"]
        source = report["source_binding"]["source"]
        return SemanticContinuationScope(
            occurrence_id=report["source_binding"]["bindings"]["occurrence_id"],
            continuation_digest=source["spec_digest"],
            continuation_sql_digest=source["continuation_sql_digest"],
            result_contract_digest=self.result_contract_digest,
            necessity_proof_digest=_hash(report),descriptor_digest=self.digest)


def _mint_continuation_refinement(
    *, source: BoundNecessitySource, evidence: NecessityEvidence,
    base_gamma: GammaSnapshot, schema_claims: list[dict[str,Any]] | tuple[dict[str,Any],...],
) -> ContinuationRefinement:
    """Trusted adapter edge after actual schema/safe-read validation.

    Schema rows here are bound premises, not an independent PG observation.
    The adapter must issue the matching Gamma fact from its actual observation
    and recheck these premises before running the scoped complete query.
    """
    report = require_necessity_evidence(evidence,source)
    base = _gamma_payload(base_gamma)
    binding = report["source_binding"]["bindings"]
    if (binding["gamma_snapshot_digest"] != base["legacy_digest"]
        or binding["snapshot_id"] != base["snapshot_id"]):
        raise NecessityError("necessity proof belongs to another upstream Gamma")
    schema = _validate_schema_claims(report,schema_claims)
    result = ContinuationRefinement(_json(report),_json(schema),_json(base),source.spec.result_contract_digest)
    key = id(result)
    def drop(reference):
        old = _REGISTERED.get(key)
        if old is not None and old[0] is reference:
            _REGISTERED.pop(key,None)
    _REGISTERED[key] = (weakref.ref(result,drop),source,evidence,base_gamma,result.digest)
    return result


def require_continuation_refinement(
    descriptor: ContinuationRefinement, *, target: PolicyAccessTarget | None = None,
    rid_column: str | None = None, query_predicate: str | None = None,
    gamma: GammaSnapshot | None = None,
) -> dict[str,Any]:
    if type(descriptor) is not ContinuationRefinement:
        raise NecessityError("exact continuation refinement descriptor required")
    record = _REGISTERED.get(id(descriptor))
    if record is None or record[0]() is not descriptor or record[4] != descriptor.digest:
        raise NecessityError("refinement lacks current local proof provenance")
    source,evidence,upstream = record[1:4]
    report = require_necessity_evidence(evidence,source)
    payload = descriptor.to_dict()
    if (_json(payload["necessity"]) != _json(report)
        or _json(payload["base_gamma"]) != _json(_gamma_payload(upstream))
        or payload["result_contract_digest"] != source.spec.result_contract_digest
        or payload["schema_claims"] != _validate_schema_claims(report,payload["schema_claims"])):
        raise NecessityError("refinement source or premises changed after issuance")
    bindings = report["source_binding"]["bindings"]
    context = target,rid_column,query_predicate,gamma
    if any(value is not None for value in context):
        if (type(target) is not PolicyAccessTarget or type(gamma) is not GammaSnapshot
            or target.to_dict() != bindings["target"] or rid_column != bindings["rid_column"]
            or query_predicate != bindings["q_predicate_sql"]):
            raise NecessityError("refinement target/query/occurrence context mismatch")
        current = _gamma_payload(gamma)
        if current["snapshot_id"] != payload["base_gamma"]["snapshot_id"]:
            raise NecessityError("refinement Gamma snapshot changed")
        facts = {fact["fact_id"]:fact for fact in current["facts"]}
        if any(facts.get(fact["fact_id"]) != fact for fact in payload["base_gamma"]["facts"]):
            raise NecessityError("refinement Gamma does not retain its exact upstream facts")
    return payload
