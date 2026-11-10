"""SQL emitter for the finite CAPRLS plan-tree IR fragment."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from .contracts import (
    AuthorizationViewBinding,
    NativeRLSSessionContract,
    canonical_predicate_digest,
    template_definition,
)
from .verifier.static import native_rls_policy_fingerprint_comment

from .ir import (
    BarrierEnforce,
    Boundary,
    DuplicateCollapse,
    InnerJoin,
    Materialize,
    PlanNode,
    Project,
    RCheck,
    Root,
    ScanOrdinary,
    ScanProtected,
    Select,
    SortEnforce,
    UnionTagged,
    UnsafeExpr,
    ValidationGate,
)


@dataclass(frozen=True)
class EmitContext:
    default_relation: str = "document"
    default_alias: str = "d"
    default_rid_col: str = "doc_id"
    schema: str = "public"
    occurrence_relations: Mapping[str, str] = field(default_factory=dict)
    occurrence_aliases: Mapping[str, str] = field(default_factory=dict)
    occurrence_rid_cols: Mapping[str, str] = field(default_factory=dict)
    exact_predicates: Mapping[str, str] = field(default_factory=dict)
    guard_predicates: Mapping[str, str] = field(default_factory=dict)
    residual_predicates: Mapping[str, str] = field(default_factory=dict)
    query_predicates: Mapping[str, str] = field(default_factory=dict)
    artifact_expectations: Mapping[str, Any] = field(default_factory=dict)
    template_params: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    unsafe_log_params: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    # These are typed execution bindings, not inferred names.  A template that
    # needs either one fails closed when the corresponding evidence is absent.
    authorization_views: Mapping[str, AuthorizationViewBinding] = field(default_factory=dict)
    native_rls_contracts: Mapping[str, NativeRLSSessionContract] = field(default_factory=dict)
    # Unsafe/raw positive controls are executable only through an explicit
    # diagnostic harness. Production callers receive the default False.
    allow_diagnostic_lowering: bool = False

    def relation_for(self, occurrence_id: str) -> str:
        return str(self.occurrence_relations.get(occurrence_id, self.default_relation))

    def alias_for(self, occurrence_id: str) -> str:
        return _ident(str(self.occurrence_aliases.get(occurrence_id, self.default_alias)))

    def rid_col_for(self, occurrence_id: str) -> str:
        return _ident(str(self.occurrence_rid_cols.get(occurrence_id, self.default_rid_col)))

    def exact_predicate_for(self, occurrence_id: str) -> str:
        return str(self.exact_predicates.get(occurrence_id, "<exact_policy>"))

    def guard_predicate_for(self, occurrence_id: str) -> str:
        return str(self.guard_predicates.get(occurrence_id, "<complete_guard>"))

    def query_predicate_for(self, occurrence_id: str) -> str:
        return str(self.query_predicates.get(occurrence_id, "<ordinary_query_predicate>"))

    def residual_predicate_for(self, residual_id: str, occurrence_id: str | None = None) -> str:
        if occurrence_id:
            occurrence_key = f"{occurrence_id}:{residual_id}"
            if occurrence_key in self.residual_predicates:
                return str(self.residual_predicates[occurrence_key])
        return str(self.residual_predicates.get(residual_id, "<exact_residual>"))

    def template_param_for(self, occurrence_id: str, key: str, default: object | None = None) -> object | None:
        return dict(self.template_params.get(occurrence_id, {})).get(key, default)

    def artifact_id_for(self, occurrence_id: str, kind: str) -> str | None:
        params = self.template_params.get(occurrence_id, {})
        artifact_ids = params.get("artifact_ids", {})
        if isinstance(artifact_ids, Mapping) and artifact_ids.get(kind):
            return str(artifact_ids[kind])
        direct = params.get(f"{kind}_artifact_id")
        return None if direct in {None, ""} else str(direct)

    def unsafe_param_for(self, expr_label: str, key: str, default: object) -> object:
        params = self.unsafe_log_params.get(expr_label, {})
        return params.get(key, default)

    def authorization_view_for(self, occurrence_id: str) -> AuthorizationViewBinding | None:
        return self.authorization_views.get(occurrence_id)

    def native_rls_contract_for(self, occurrence_id: str) -> NativeRLSSessionContract | None:
        return self.native_rls_contracts.get(occurrence_id)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _freeze_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json_value(value[key]) for key in sorted(value, key=str)}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TemplateLoweringError("artifact validation expectation has an unsupported JSON value")


def _thaw_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json_value(item) for item in value]
    return value


def _freeze_json_payload(value: object) -> Any:
    """Take a JSON-only snapshot for a validator recipe.

    Artifact expectations cross the planner/runtime boundary.  Keeping a
    caller-owned dict here would allow the validation input to change after
    the SQL draft/certificate was frozen, so normalize it through JSON and
    expose an immutable top-level mapping instead.
    """

    if not isinstance(value, (Mapping, list, tuple)):
        raise TemplateLoweringError(
            "artifact validation expectation must be a JSON mapping or sequence"
        )
    try:
        json_input = dict(value) if isinstance(value, Mapping) else list(value)
        canonical = _canonical_json(json_input)
        normalized = json.loads(canonical)
    except (TypeError, ValueError) as exc:
        raise TemplateLoweringError(
            "artifact validation expectation must be JSON-serializable"
        ) from exc
    if not isinstance(normalized, (dict, list)):  # defensive: json decoder contract
        raise TemplateLoweringError(
            "artifact validation expectation must decode to a mapping or sequence"
        )
    return _freeze_json_value(normalized)


ARTIFACT_EXPECTATION_SCHEMA = "caprls_artifact_expectation"
ARTIFACT_EXPECTATION_VERSION = 1
ARTIFACT_DYNAMIC_RECIPE_SCHEMA = "caprls_artifact_dynamic_recipe"
ARTIFACT_DYNAMIC_RECIPE_VERSION = 2
ARTIFACT_DYNAMIC_CHECK_KINDS = (
    "artifact_context",
    "artifact_freshness",
    "artifact_toctou",
)
ARTIFACT_H2_COMPONENT_DEP_KINDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "freshness": frozenset({"policy", "membership", "acl", "base"}),
        "context": frozenset({"context", "context_scope", "context_hash"}),
        "snapshot": frozenset({"toctou", "execution_snapshot"}),
        "trusted_read": frozenset({"policy", "membership", "acl"}),
        "rid_materialization": frozenset(
            {
                "rid_domain",
                "rid_domain_id",
                "base_rel_oid",
                "base_relation",
                "rid_props",
            }
        ),
    }
)


@dataclass(frozen=True, order=True)
class ArtifactDependencyIdentity:
    dep_kind: str
    dep_name: str

    def __post_init__(self) -> None:
        if (
            self.dep_kind.__class__ is not str
            or not self.dep_kind
            or self.dep_name.__class__ is not str
            or not self.dep_name
        ):
            raise TemplateLoweringError(
                "artifact dependency identity requires nonempty exact strings"
            )

    def to_dict(self) -> dict[str, str]:
        self.__post_init__()
        return {"dep_kind": self.dep_kind, "dep_name": self.dep_name}


@dataclass(frozen=True, order=True)
class ArtifactDependencyExpectation:
    dep_kind: str
    dep_name: str
    version_at_build: int

    def __post_init__(self) -> None:
        ArtifactDependencyIdentity(self.dep_kind, self.dep_name)
        if (
            self.version_at_build.__class__ is not int
            or self.version_at_build < 0
        ):
            raise TemplateLoweringError(
                "artifact dependency version_at_build must be a nonnegative integer"
            )

    @property
    def identity(self) -> ArtifactDependencyIdentity:
        self.__post_init__()
        return ArtifactDependencyIdentity(self.dep_kind, self.dep_name)

    def to_dict(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "dep_kind": self.dep_kind,
            "dep_name": self.dep_name,
            "version_at_build": self.version_at_build,
        }


@dataclass(frozen=True)
class ArtifactComponentBinding:
    component: str
    dependencies: tuple[ArtifactDependencyIdentity, ...]

    def __post_init__(self) -> None:
        if (
            self.component.__class__ is not str
            or self.component not in ARTIFACT_H2_COMPONENT_DEP_KINDS
        ):
            raise TemplateLoweringError(
                "artifact component binding has an unknown component"
            )
        try:
            dependencies = tuple(self.dependencies)
        except TypeError as exc:
            raise TemplateLoweringError(
                "artifact component binding requires typed dependency identities"
            ) from exc
        if (
            not dependencies
            or any(item.__class__ is not ArtifactDependencyIdentity for item in dependencies)
        ):
            raise TemplateLoweringError(
                "artifact component binding requires typed dependency identities"
            )
        for item in dependencies:
            item.__post_init__()
            if item.dep_kind not in ARTIFACT_H2_COMPONENT_DEP_KINDS[self.component]:
                raise TemplateLoweringError(
                    f"artifact component {self.component} cannot use dependency kind "
                    + item.dep_kind
                )
        canonical = tuple(sorted(dependencies))
        if len(set(canonical)) != len(canonical):
            raise TemplateLoweringError(
                "artifact component binding contains duplicate dependency identities"
            )
        # Revalidation must retain an already canonical tuple.  Serialization
        # replays this validator, and replacing an equal tuple needlessly
        # invalidates observations of this frozen identity graph.  All kind,
        # exact-type, duplicate and ordering checks above still run.
        if type(self.dependencies) is not tuple or any(
            current is not ordered
            for current, ordered in zip(self.dependencies, canonical)
        ):
            object.__setattr__(self, "dependencies", canonical)

    def to_dict(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "component": self.component,
            "dependencies": [item.to_dict() for item in self.dependencies],
        }


@dataclass(frozen=True)
class StrictArtifactExpectation:
    dependencies: tuple[ArtifactDependencyExpectation, ...]
    component_bindings: tuple[ArtifactComponentBinding, ...]
    schema: str = ARTIFACT_EXPECTATION_SCHEMA
    version: int = ARTIFACT_EXPECTATION_VERSION
    _construction_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            dependencies = tuple(self.dependencies)
            bindings = tuple(self.component_bindings)
        except TypeError as exc:
            raise TemplateLoweringError(
                "strict artifact expectation requires typed dependency rows and bindings"
            ) from exc
        canonical_dependencies, canonical_bindings = self._validate(
            dependencies,
            bindings,
            require_canonical=False,
        )
        object.__setattr__(self, "dependencies", canonical_dependencies)
        object.__setattr__(self, "component_bindings", canonical_bindings)
        object.__setattr__(
            self,
            "_construction_digest",
            self._current_digest(),
        )

    def _validate(
        self,
        dependencies: tuple[ArtifactDependencyExpectation, ...],
        bindings: tuple[ArtifactComponentBinding, ...],
        *,
        require_canonical: bool,
    ) -> tuple[
        tuple[ArtifactDependencyExpectation, ...],
        tuple[ArtifactComponentBinding, ...],
    ]:
        if (
            self.schema.__class__ is not str
            or self.schema != ARTIFACT_EXPECTATION_SCHEMA
            or self.version.__class__ is not int
            or self.version != ARTIFACT_EXPECTATION_VERSION
        ):
            raise TemplateLoweringError("artifact expectation schema/version is unsupported")
        if not dependencies or any(
            item.__class__ is not ArtifactDependencyExpectation for item in dependencies
        ):
            raise TemplateLoweringError(
                "strict artifact expectation requires nonempty typed dependency rows"
            )
        for item in dependencies:
            item.__post_init__()
        canonical_dependencies = tuple(
            sorted(dependencies, key=lambda item: (item.dep_kind, item.dep_name))
        )
        identities = tuple(item.identity for item in canonical_dependencies)
        if len(set(identities)) != len(identities):
            raise TemplateLoweringError(
                "strict artifact expectation contains duplicate dependency identity"
            )
        if any(item.__class__ is not ArtifactComponentBinding for item in bindings):
            raise TemplateLoweringError(
                "strict artifact expectation requires typed component bindings"
            )
        for item in bindings:
            item.__post_init__()
        canonical_bindings = tuple(sorted(bindings, key=lambda item: item.component))
        components = tuple(item.component for item in canonical_bindings)
        if set(components) != set(ARTIFACT_H2_COMPONENT_DEP_KINDS) or len(components) != len(
            ARTIFACT_H2_COMPONENT_DEP_KINDS
        ):
            raise TemplateLoweringError(
                "strict artifact expectation must bind exactly all H2 components"
            )
        known = set(identities)
        consumed: set[ArtifactDependencyIdentity] = set()
        for binding in canonical_bindings:
            for identity in binding.dependencies:
                if identity not in known:
                    raise TemplateLoweringError(
                        "artifact component binding references an unknown dependency"
                    )
                consumed.add(identity)
        if consumed != known:
            raise TemplateLoweringError(
                "strict artifact expectation contains an unconsumed dependency"
            )
        if require_canonical and (
            dependencies != canonical_dependencies or bindings != canonical_bindings
        ):
            raise TemplateLoweringError("strict artifact expectation is not canonical")
        return canonical_dependencies, canonical_bindings

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "component_bindings": [item.to_dict() for item in self.component_bindings],
        }

    def _current_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            _canonical_json(self._identity_payload()).encode("utf-8")
        ).hexdigest()

    def assert_valid(self) -> None:
        self._validate(
            tuple(self.dependencies),
            tuple(self.component_bindings),
            require_canonical=True,
        )
        if self._current_digest() != self._construction_digest:
            raise TemplateLoweringError(
                "strict artifact expectation changed after construction"
            )

    @property
    def digest(self) -> str:
        self.assert_valid()
        return self._construction_digest

    def dependency_rows(self) -> tuple[dict[str, Any], ...]:
        self.assert_valid()
        return tuple(item.to_dict() for item in self.dependencies)

    def component_payload(self) -> tuple[dict[str, Any], ...]:
        self.assert_valid()
        return tuple(item.to_dict() for item in self.component_bindings)

    def to_dict(self) -> dict[str, Any]:
        self.assert_valid()
        return self._identity_payload()


@dataclass(frozen=True)
class ArtifactValidationRecipe:
    """A typed, immutable H2 recipe detached from the query SQL body.

    The historical ``render()`` method retains its transaction-script view
    for diagnostic compatibility.  Strict execution instead consumes this
    object after plain EXPLAIN in the same repeatable-read transaction, while
    ``render_core()`` contains exactly the protected query statement.
    """

    artifact_id: str
    expected: Any
    expectation_declared: bool
    gate_path: tuple[str, ...]
    occurrence_id: str
    template_id: str
    required_checks: tuple[str, ...] = ARTIFACT_DYNAMIC_CHECK_KINDS

    def __post_init__(self) -> None:
        if self.artifact_id.__class__ is not str or not self.artifact_id:
            raise TemplateLoweringError("artifact validation recipe requires artifact_id")
        try:
            path = tuple(self.gate_path)
        except TypeError as exc:
            raise TemplateLoweringError(
                "artifact validation recipe requires a gate path"
            ) from exc
        if not path or any(item.__class__ is not str or not item for item in path):
            raise TemplateLoweringError("artifact validation recipe requires a gate path")
        if (
            self.occurrence_id.__class__ is not str
            or not self.occurrence_id
            or self.template_id.__class__ is not str
            or not self.template_id
        ):
            raise TemplateLoweringError(
                "artifact validation recipe requires protected occurrence/template identity"
            )
        try:
            raw_required_checks = tuple(self.required_checks)
        except TypeError as exc:
            raise TemplateLoweringError(
                "artifact validation recipe requires explicit H2 checks"
            ) from exc
        if not raw_required_checks or any(
            item.__class__ is not str or not item for item in raw_required_checks
        ):
            raise TemplateLoweringError("artifact validation recipe requires explicit H2 checks")
        required_checks = tuple(sorted(set(raw_required_checks)))
        object.__setattr__(self, "gate_path", path)
        object.__setattr__(self, "required_checks", required_checks)
        if self.expected.__class__ is StrictArtifactExpectation:
            self.expected.assert_valid()
        else:
            object.__setattr__(self, "expected", _freeze_json_payload(self.expected))

    def _database_expected_rows(self) -> Any:
        if self.expected.__class__ is StrictArtifactExpectation:
            return list(self.expected.dependency_rows())
        return _thaw_json_value(self.expected)

    @property
    def expected_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            _canonical_json(self._database_expected_rows()).encode("utf-8")
        ).hexdigest()

    @property
    def complete(self) -> bool:
        # An absent/empty expectation is not sufficient for strict H2.  The
        # legacy renderer still accepts it for historical diagnostics, but
        # strict planning must fail closed before an executable draft exists.
        if (
            self.expectation_declared.__class__ is not bool
            or not self.expectation_declared
            or self.expected.__class__ is not StrictArtifactExpectation
            or self.required_checks != ARTIFACT_DYNAMIC_CHECK_KINDS
        ):
            return False
        try:
            self.expected.assert_valid()
        except TemplateLoweringError:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": (
                "artifact_validation_recipe_v2"
                if self.expected.__class__ is StrictArtifactExpectation
                else "artifact_validation_recipe_v1"
            ),
            "artifact_id": self.artifact_id,
            "expected": (
                self.expected.to_dict()
                if self.expected.__class__ is StrictArtifactExpectation
                else _thaw_json_value(self.expected)
            ),
            "expected_digest": self.expected_digest,
            "gate_path": list(self.gate_path),
            "occurrence_id": self.occurrence_id,
            "template_id": self.template_id,
            "required_checks": list(self.required_checks),
        }
        return payload

    def to_dynamic_recipe_payload(self) -> dict[str, Any]:
        """Return the exact H2 payload consumed by ``DynamicObligation``.

        The execution module owns the canonical digest format, so import it
        lazily to keep the emitter independent at module initialization.
        """

        from .execution import canonical_dynamic_recipe_digest

        if (
            self.expected.__class__ is not StrictArtifactExpectation
            or self.required_checks != ARTIFACT_DYNAMIC_CHECK_KINDS
        ):
            raise TemplateLoweringError(
                "strict dynamic artifact recipe requires StrictArtifactExpectation"
            )
        self.expected.assert_valid()
        expected_rows = list(self.expected.dependency_rows())
        component_bindings = list(self.expected.component_payload())
        return {
            "schema": ARTIFACT_DYNAMIC_RECIPE_SCHEMA,
            "version": ARTIFACT_DYNAMIC_RECIPE_VERSION,
            "artifact_id": self.artifact_id,
            "expected_dependency_digest": canonical_dynamic_recipe_digest(
                {"dependency_rows": expected_rows}
            ),
            "expected_dependency_rows": expected_rows,
            "component_bindings_digest": canonical_dynamic_recipe_digest(
                {"component_bindings": component_bindings}
            ),
            "component_bindings": component_bindings,
            "gate_path": self.gate_path,
            "occurrence_id": self.occurrence_id,
            "template_id": self.template_id,
            "required_check_kinds": self.required_checks,
        }

    def render_validator_sql(self) -> str:
        return (
            "SELECT public.caprls_assert_artifact_valid("
            f"{_literal(self.artifact_id)}, {_jsonb_literal(self._database_expected_rows())})"
        )


@dataclass(frozen=True)
class SQLFragment:
    body: str
    ctes: tuple[str, ...] = ()
    validation_statements: tuple[str, ...] = ()
    validation_recipes: tuple[ArtifactValidationRecipe, ...] = ()

    def render_core(self) -> str:
        """Render only the one protected query statement for strict drafts."""

        query = self.body
        if self.ctes:
            query = "WITH " + ",\n".join(self.ctes) + "\n" + self.body
        return query.rstrip(";") + ";"

    def render(self) -> str:
        query = self.render_core().rstrip(";")
        validation_statements = (
            tuple(recipe.render_validator_sql() for recipe in self.validation_recipes)
            if self.validation_recipes
            else self.validation_statements
        )
        if validation_statements:
            statements: list[str] = ["BEGIN ISOLATION LEVEL REPEATABLE READ"]
            statements.extend(validation_statements)
            statements.append(query)
            statements.append("COMMIT")
        else:
            statements = [query]
        return ";\n".join(statement.rstrip(";") for statement in statements) + ";"


def emit_sql(node: PlanNode, context: EmitContext | None = None) -> SQLFragment:
    ctx = context or EmitContext()
    fragment = _emit(node, ctx)
    return SQLFragment(
        body=fragment.body,
        ctes=fragment.ctes,
        validation_statements=fragment.validation_statements,
        validation_recipes=_validation_recipes_for(node, ctx),
    )


class TemplateLoweringError(ValueError):
    """Raised when a protected template has no valid executable lowering."""


def _ident(value: str) -> str:
    normalized = value.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized):
        raise ValueError(f"unsafe SQL identifier: {value!r}")
    return normalized


def _qualified_relation(schema: str, relation: str) -> str:
    return f"{_ident(schema)}.{_ident(relation)}"


def _qualified_relation_value(schema: str, relation: object) -> str:
    value = str(relation)
    if "." in value:
        schema_name, rel_name = value.split(".", 1)
        return f"{_ident(schema_name)}.{_ident(rel_name)}"
    return _qualified_relation(schema, value)


def _literal(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _jsonb_literal(payload: object) -> str:
    return _literal(json.dumps(payload, sort_keys=True, separators=(",", ":"))) + "::jsonb"


def _cte_name(prefix: str, namespace: str = "") -> str:
    if not namespace:
        return _ident(prefix)
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", namespace).strip("_")
    return _ident(f"{prefix}_{cleaned or 'anon'}")


def _subquery(fragment: SQLFragment, alias: str) -> str:
    return f"({fragment.body}) AS {_ident(alias)}"


def _combine(
    body: str,
    *children: SQLFragment,
    ctes: Iterable[str] = (),
    validation_statements: Iterable[str] = (),
    validation_recipes: Iterable[ArtifactValidationRecipe] = (),
) -> SQLFragment:
    merged_ctes: list[str] = []
    merged_validations: list[str] = []
    merged_recipes: list[ArtifactValidationRecipe] = []
    for child in children:
        merged_ctes.extend(child.ctes)
        merged_validations.extend(child.validation_statements)
        merged_recipes.extend(child.validation_recipes)
    merged_ctes.extend(ctes)
    merged_validations.extend(validation_statements)
    merged_recipes.extend(validation_recipes)
    return SQLFragment(
        body=body,
        ctes=tuple(merged_ctes),
        validation_statements=tuple(merged_validations),
        validation_recipes=tuple(merged_recipes),
    )


def _child_namespace(namespace: str, child: str) -> str:
    return f"{namespace}_{child}" if namespace else child


def _artifact_conditions(
    ctx: EmitContext,
    occurrence_id: str,
    *,
    alias: str,
    kind: str,
    keyed: bool = False,
) -> tuple[str, ...]:
    """Return a complete, occurrence-bound artifact scope or reject.

    Artifact tables are shared across policies and contexts.  Omitting any of
    these identities used to produce a syntactically valid but over-broad
    authorization scan.  Deriving a default from the relation is not a safe
    substitute for freezing the planner's intended scope, so enabled artifact
    lowerers require every field explicitly before emitting SQL.
    """

    conditions: list[str] = []
    artifact_id = ctx.artifact_id_for(occurrence_id, kind)
    values: dict[str, object | None] = {"artifact_id": artifact_id}
    for param_key in ("policy_id", "user_id", "ctx_hash", "rid_domain_id", "base_rel_oid"):
        values[param_key] = ctx.template_param_for(occurrence_id, param_key)
    missing = sorted(key for key, value in values.items() if value in {None, ""})
    if missing:
        raise TemplateLoweringError(
            f"{kind} lowering requires complete artifact scope for {occurrence_id}: "
            + ", ".join(missing)
        )
    conditions.append(f"{alias}.artifact_id = {_literal(str(artifact_id))}")
    for param_key, column in (
        ("policy_id", "policy_id"),
        ("user_id", "user_id"),
        ("ctx_hash", "ctx_hash"),
    ):
        conditions.append(f"{alias}.{column} = {_literal(values[param_key])}")
    if keyed:
        key_name = ctx.template_param_for(occurrence_id, "key_name")
        key_predicate = ctx.template_param_for(occurrence_id, "key_predicate")
        if key_name in {None, ""} or key_predicate in {None, ""}:
            raise TemplateLoweringError(
                f"{kind} lowering requires key_name and a controlled key predicate for {occurrence_id}"
            )
        conditions.append(f"{alias}.key_name = {_literal(key_name)}")
        conditions.append(str(key_predicate))
    conditions.append(f"{alias}.rid_domain_id = {_literal(values['rid_domain_id'])}")
    conditions.append(f"{alias}.base_rel_oid = {_literal(values['base_rel_oid'])}::regclass::oid")
    return tuple(conditions)


def _where_clause(conditions: Iterable[str]) -> str:
    rendered = tuple(condition for condition in conditions if condition)
    return "" if not rendered else " WHERE " + " AND ".join(rendered)


def _carrier_columns_for(ctx: EmitContext, occurrence_id: str, relation: str, rid_col: str) -> tuple[str, ...]:
    configured = ctx.template_param_for(occurrence_id, "carrier_columns")
    if isinstance(configured, Iterable) and not isinstance(configured, (str, bytes)):
        columns = tuple(_ident(str(column)) for column in configured)
    elif relation == "document":
        columns = (rid_col, "tenant_id", "owner_id", "public")
    elif relation == "ticket":
        columns = (rid_col, "tenant_id", "owner_id", "status", "priority")
    elif relation == "invoice":
        columns = (rid_col, "region", "account_id")
    else:
        columns = (rid_col,)
    if rid_col not in columns:
        columns = (rid_col, *columns)
    return columns


def _carrier_projection_sql(ctx: EmitContext, occurrence_id: str, relation: str, alias: str, rid_col: str) -> str:
    columns = _carrier_columns_for(ctx, occurrence_id, relation, rid_col)
    rendered = [f"{alias}.{column}" for column in columns]
    rendered.append(f"{alias}.{rid_col} AS __rid")
    return ", ".join(rendered)


def _single_protected_occurrence_id(node: PlanNode) -> str | None:
    occurrences = {
        candidate.occurrence_id
        for candidate in node.children()
        if isinstance(candidate, ScanProtected)
    }
    if isinstance(node, ScanProtected):
        occurrences.add(node.occurrence_id)
    for child in node.children():
        child_occurrence = _single_protected_occurrence_id(child)
        if child_occurrence:
            occurrences.add(child_occurrence)
    if len(occurrences) == 1:
        return next(iter(occurrences))
    return None


def _single_protected_scan(node: PlanNode) -> ScanProtected | None:
    """Return the sole protected scan below a validation gate, if unique."""

    scans: list[ScanProtected] = []

    def visit(current: PlanNode) -> None:
        if isinstance(current, ScanProtected):
            scans.append(current)
            return
        for child in current.children():
            visit(child)

    visit(node)
    if len(scans) != 1:
        return None
    return scans[0]


def _validation_recipes_for(node: PlanNode, ctx: EmitContext) -> tuple[ArtifactValidationRecipe, ...]:
    """Derive every ValidationGate recipe from the actual bound IR.

    This separate traversal intentionally does not trust the historical
    multi-statement SQL script.  Its path convention mirrors the finite IR
    transfer/certificate path convention, so replay can prove that every
    gate is attached to the selected protected occurrence exactly once.
    """

    recipes: list[ArtifactValidationRecipe] = []

    def visit(current: PlanNode, path: tuple[str, ...]) -> None:
        if isinstance(current, ValidationGate):
            # Child-first matches the legacy script's execution order:
            # nested gates validate their child before the outer gate.
            visit(current.source, (*path, "source"))
            scan = _single_protected_scan(current.source)
            if scan is None:
                raise TemplateLoweringError(
                    "ValidationGate must enclose exactly one protected scan for strict recipe binding"
                )
            declared = current.artifact_id in ctx.artifact_expectations
            raw_expected = ctx.artifact_expectations.get(current.artifact_id, {})
            recipes.append(
                ArtifactValidationRecipe(
                    artifact_id=current.artifact_id,
                    expected=raw_expected,
                    expectation_declared=declared,
                    gate_path=path,
                    occurrence_id=scan.occurrence_id,
                    template_id=scan.template_slot,
                )
            )
            return
        if isinstance(current, InnerJoin):
            visit(current.left, (*path, "left"))
            visit(current.right, (*path, "right"))
            return
        if isinstance(current, UnionTagged):
            for index, branch in enumerate(current.branches):
                visit(branch, (*path, f"branches[{index}]"))
            return
        if isinstance(current, ScanProtected) or isinstance(current, ScanOrdinary):
            return
        children = current.children()
        if len(children) == 1:
            visit(children[0], (*path, "source"))
            return
        if not children:
            return
        raise TemplateLoweringError(
            f"unsupported multi-child node in validation recipe traversal: {current!r}"
        )

    visit(node, ("root",))
    return tuple(recipes)


def _scan_parts(
    node: ScanProtected, ctx: EmitContext
) -> tuple[str, str, str, str, str]:
    occurrence_id = node.occurrence_id
    relation = ctx.relation_for(occurrence_id)
    alias = ctx.alias_for(occurrence_id)
    rid_col = ctx.rid_col_for(occurrence_id)
    return (
        occurrence_id,
        relation,
        alias,
        rid_col,
        _qualified_relation(ctx.schema, relation),
    )


def _lower_barrier_filter(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    cte = _cte_name("auth", namespace)
    return SQLFragment(
        body=f"SELECT * FROM {cte}",
        ctes=(
            f"{cte} AS MATERIALIZED ("
            f"SELECT {_carrier_projection_sql(ctx, occurrence_id, relation, alias, rid_col)} "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.exact_predicate_for(occurrence_id)})",
        ),
    )


def _lower_query_filtered_barrier_filter(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    exact_predicate = ctx.exact_predicate_for(occurrence_id)
    query_predicate = ctx.query_predicate_for(occurrence_id)
    if exact_predicate.strip() in {"", "<exact_policy>", "<policy_predicate>"}:
        raise TemplateLoweringError(
            "barrier_filter_query_v1 requires a concrete policy predicate"
        )
    if query_predicate.strip() in {"", "<ordinary_query_predicate>", "<safe_query>"}:
        raise TemplateLoweringError(
            "barrier_filter_query_v1 requires a concrete query predicate"
        )
    cte = _cte_name("auth", namespace)
    columns = _carrier_columns_for(ctx, occurrence_id, relation, rid_col)
    projection = ", ".join(f"{alias}.{column}" for column in columns)
    return SQLFragment(
        # Keep the base RID in the protected producer, but derive its equal
        # hidden alias after materialization. The output schema and bag are
        # unchanged; the tuplestore need not carry the same RID twice.
        body=f"SELECT {cte}.*, {cte}.{_ident(rid_col)} AS __rid FROM {cte}",
        ctes=(
            f"{cte} AS MATERIALIZED ("
            f"SELECT {projection} "
            f"FROM {qualified} {alias} "
            f"WHERE ({exact_predicate}) AND ({query_predicate}))",
        ),
    )


def _lower_continuation_filtered_barrier_filter(
    node: ScanProtected, ctx: EmitContext, namespace: str,
) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node,ctx)
    predicate = ctx.template_param_for(occurrence_id,"continuation_necessary_predicate")
    digest = ctx.template_param_for(occurrence_id,"continuation_refinement_digest")
    if (type(predicate) is not str or not predicate.strip()
        or type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}",digest) is None
        or ctx.template_param_for(occurrence_id,"continuation_protected_alias") != alias):
        raise TemplateLoweringError("continuation-filtered barrier lacks its exact predicate/source binding")
    policy = ctx.exact_predicate_for(occurrence_id)
    query = ctx.query_predicate_for(occurrence_id)
    if not policy.strip() or not query.strip() or re.search(r"<\w+>",policy+query):
        raise TemplateLoweringError("continuation-filtered barrier requires concrete policy/query predicates")
    cte = _cte_name("auth",namespace)
    return SQLFragment(body=f"SELECT * FROM {cte}",ctes=(
        f"{cte} AS MATERIALIZED (SELECT {_carrier_projection_sql(ctx,occurrence_id,relation,alias,rid_col)} "
        f"FROM {qualified} {alias} WHERE ({policy}) AND (({query}) AND ({predicate})))",))


def _lower_inline_barrier_filter(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    cte = _cte_name("auth", namespace)
    return SQLFragment(
        body=f"SELECT * FROM {cte}",
        ctes=(
            f"{cte} AS NOT MATERIALIZED ("
            f"SELECT {_carrier_projection_sql(ctx, occurrence_id, relation, alias, rid_col)} "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.exact_predicate_for(occurrence_id)})",
        ),
    )


def _lower_safe_predicate_injection(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    del namespace
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.query_predicate_for(occurrence_id)} "
            f"AND {ctx.exact_predicate_for(occurrence_id)}"
        )
    )


def _lower_ordinary_first_exact_check(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    # The SQL shape is intentionally the same conjunction as safe injection;
    # the distinction is the licensed query-filtered target in κ/rho.
    return _lower_safe_predicate_injection(node, ctx, namespace)


def _lower_diagnostic_only_scan(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    # Diagnostic-only templates (e.g. the E1 unsafe-raw-pushdown positive
    # control) are deliberately kept out of PROTECTED_SCAN_LOWERERS so they
    # can never satisfy the production template registry and can never
    # accidentally become a default planner candidate (see
    # contracts.validate_implementation_capabilities: an entry here would be
    # flagged as an orphan lowering). This is the single, shared "no
    # protection applied" scan every diagnostic template lowers to; the
    # surrounding IR (a Select for the ordinary query predicate, an
    # UnsafeExpr for the unsafe_log call) supplies everything else.
    del namespace
    _occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {qualified} {alias}"
        )
    )


def _lower_native_pg_rls(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    del namespace
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    contract = ctx.native_rls_contract_for(occurrence_id)
    if contract is None:
        raise TemplateLoweringError(
            f"native_pg_rls_v1 requires a typed NativeRLSSessionContract for {occurrence_id}"
        )
    policy_id = ctx.template_param_for(occurrence_id, "policy_id")
    if policy_id in {None, ""}:
        raise TemplateLoweringError(
            f"native_pg_rls_v1 requires an explicit policy binding for {occurrence_id}"
        )
    if not contract.matches(relation=relation, policy_id=str(policy_id)):
        raise TemplateLoweringError(
            f"native_pg_rls_v1 received an invalid RLS contract for {occurrence_id}"
        )
    if str(policy_id) != contract.policy_id:
        raise TemplateLoweringError(
            f"native_pg_rls_v1 policy binding mismatch for {occurrence_id}"
        )
    policy_predicate = ctx.exact_predicate_for(occurrence_id)
    if policy_predicate.strip() in {"", "<exact_policy>", "<policy_predicate>"}:
        raise TemplateLoweringError(
            f"native_pg_rls_v1 requires a concrete policy predicate fingerprint for {occurrence_id}"
        )
    if contract.emitted_policy_digest != canonical_predicate_digest(policy_predicate):
        raise TemplateLoweringError(
            f"native_pg_rls_v1 policy predicate does not match its session contract for {occurrence_id}"
        )
    return SQLFragment(
        body=(
            f"{native_rls_policy_fingerprint_comment(policy_predicate)} "
            f"/* caprls_native_rls_contract:{contract.policy_fingerprint}:"
            f"{contract.emitted_policy_digest} */ "
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.query_predicate_for(occurrence_id)}"
        )
    )


def _lower_auth_view_scan(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    del namespace
    occurrence_id, relation, alias, rid_col, _qualified = _scan_parts(node, ctx)
    binding = ctx.authorization_view_for(occurrence_id)
    if binding is None:
        raise TemplateLoweringError(
            f"auth_view_scan_v1 requires a typed AuthorizationViewBinding for {occurrence_id}"
        )
    if binding.base_relation != relation or binding.rid_col != rid_col:
        raise TemplateLoweringError(
            f"auth_view_scan_v1 binding does not match relation/RID for {occurrence_id}"
        )
    policy_id = ctx.template_param_for(occurrence_id, "policy_id")
    if policy_id in {None, ""}:
        raise TemplateLoweringError(
            f"auth_view_scan_v1 requires an explicit policy binding for {occurrence_id}"
        )
    if str(policy_id) != binding.policy_id:
        raise TemplateLoweringError(
            f"auth_view_scan_v1 policy binding mismatch for {occurrence_id}"
        )
    if not binding.binding_id or not binding.scope_fingerprint:
        raise TemplateLoweringError(
            f"auth_view_scan_v1 binding is incomplete for {occurrence_id}"
        )
    view = _qualified_relation_value(ctx.schema, binding.view_relation)
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {view} {alias}"
        )
    )


def _lower_guard_candidate(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    cte = _cte_name("cand", namespace)
    return SQLFragment(
        body=f"SELECT * FROM {cte}",
        ctes=(
            f"{cte} AS MATERIALIZED ("
            f"SELECT {_carrier_projection_sql(ctx, occurrence_id, relation, alias, rid_col)} "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.guard_predicate_for(occurrence_id)})",
        ),
    )


def _lower_auth_index_enum(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    del namespace
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    conditions = _artifact_conditions(ctx, occurrence_id, alias="a", kind="auth_idx")
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {_ident(ctx.schema)}.auth_idx a "
            f"JOIN {qualified} {alias} ON {alias}.{rid_col} = a.rid"
            f"{_where_clause(conditions)}"
        )
    )


def _lower_auth_index_semijoin(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    del namespace
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    conditions = (
        f"a.rid = {alias}.{rid_col}",
        *_artifact_conditions(ctx, occurrence_id, alias="a", kind="auth_idx"),
    )
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.query_predicate_for(occurrence_id)} "
            f"AND EXISTS (SELECT 1 FROM {_ident(ctx.schema)}.auth_idx a "
            f"{_where_clause(conditions)})"
        )
    )


def _lower_strong_auth_index_keyed(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    del namespace
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    conditions = _artifact_conditions(
        ctx, occurrence_id, alias="a", kind="auth_idx_keyed", keyed=True
    )
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {_ident(ctx.schema)}.auth_idx_keyed a "
            f"JOIN {qualified} {alias} ON {alias}.{rid_col} = a.rid"
            f"{_where_clause(conditions)}"
        )
    )


def _lower_auth_index_keyed_semijoin(
    node: ScanProtected, ctx: EmitContext, namespace: str
) -> SQLFragment:
    del namespace
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    conditions = (
        f"a.rid = {alias}.{rid_col}",
        *_artifact_conditions(
            ctx, occurrence_id, alias="a", kind="auth_idx_keyed", keyed=True
        ),
    )
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {qualified} {alias} "
            f"WHERE {ctx.query_predicate_for(occurrence_id)} "
            f"AND EXISTS (SELECT 1 FROM {_ident(ctx.schema)}.auth_idx_keyed a "
            f"{_where_clause(conditions)})"
        )
    )


def _lower_mav_scan(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    occurrence_id, relation, alias, rid_col, _qualified = _scan_parts(node, ctx)
    mav_relation = ctx.template_param_for(
        occurrence_id, "mav_relation"
    )
    required = {
        "artifact_id": ctx.artifact_id_for(occurrence_id, "mav"),
        "policy_id": ctx.template_param_for(occurrence_id, "policy_id"),
        "user_id": ctx.template_param_for(occurrence_id, "user_id"),
        "ctx_hash": ctx.template_param_for(occurrence_id, "ctx_hash"),
        "rid_domain_id": ctx.template_param_for(occurrence_id, "rid_domain_id"),
        "base_rel_oid": ctx.template_param_for(occurrence_id, "base_rel_oid"),
        "mav_relation": mav_relation,
    }
    missing = sorted(key for key, value in required.items() if value in {None, ""})
    if missing:
        raise TemplateLoweringError(
            f"mav_scan_v1 requires complete artifact scope for {occurrence_id}: "
            + ", ".join(missing)
        )
    mav_qualified = _qualified_relation_value(ctx.schema, mav_relation)
    binding_cte = _cte_name("mav_binding", namespace)
    # A materialized view does not necessarily carry artifact metadata as
    # columns.  Bind the scanned relation to the catalog row in SQL itself,
    # rather than merely checking that caller-provided strings are non-empty.
    # The CTE must be non-empty for the MAV scan to return rows, and compares
    # artifact identity, relation OID, policy/principal/context/RID scope, and
    # the RID domain's base-relation OID in the same executable object.
    binding_sql = (
        f"{binding_cte} AS MATERIALIZED ("
        "SELECT 1 AS bound "
        "FROM caprls_catalog.artifact_catalog ac "
        "JOIN caprls_catalog.rid_domain rd ON rd.domain_id = ac.rid_domain_id "
        f"WHERE ac.artifact_id = {_literal(str(required['artifact_id']))} "
        f"AND ac.materialized_rel = {_literal(mav_qualified)}::regclass "
        f"AND ac.relname = {_literal(relation)} "
        f"AND ac.policy_id = {_literal(str(required['policy_id']))} "
        f"AND COALESCE(ac.user_scope, '') = {_literal(str(required['user_id']))} "
        f"AND COALESCE(ac.query_scope_hash, '') = {_literal(str(required['ctx_hash']))} "
        f"AND ac.rid_domain_id = {_literal(str(required['rid_domain_id']))} "
        f"AND rd.base_rel_oid = {_literal(str(required['base_rel_oid']))}::regclass::oid"
        ")"
    )
    predicate = ctx.template_param_for(
        occurrence_id, "mav_query_predicate", ctx.query_predicate_for(occurrence_id)
    )
    conditions = () if predicate in {None, "", "TRUE", "true"} else (str(predicate),)
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {mav_qualified} {alias} CROSS JOIN {binding_cte}"
            f"{_where_clause(conditions)}"
        ),
        ctes=(binding_sql,),
    )


def _lower_hybrid_intersect(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    occurrence_id, _relation, alias, rid_col, qualified = _scan_parts(node, ctx)
    q_cte = _cte_name("q", namespace)
    a_cte = _cte_name("a", namespace)
    auth_conditions = _artifact_conditions(ctx, occurrence_id, alias="ai", kind="auth_idx")
    return SQLFragment(
        body=(
            f"SELECT {alias}.*, {alias}.{rid_col} AS __rid "
            f"FROM {q_cte} q JOIN {a_cte} a USING (rid) "
            f"JOIN {qualified} {alias} ON {alias}.{rid_col} = q.rid"
        ),
        ctes=(
            f"{q_cte} AS MATERIALIZED ("
            f"SELECT {alias}.{rid_col} AS rid FROM {qualified} {alias} "
            f"WHERE {ctx.query_predicate_for(occurrence_id)})",
            f"{a_cte} AS MATERIALIZED ("
            f"SELECT ai.rid FROM {_ident(ctx.schema)}.auth_idx ai"
            f"{_where_clause(auth_conditions)})",
        ),
    )


ProtectedScanLowerer = Callable[[ScanProtected, EmitContext, str], SQLFragment]


PROTECTED_SCAN_LOWERERS: Mapping[str, ProtectedScanLowerer] = MappingProxyType(
    {
        "barrier_filter_v1": _lower_barrier_filter,
        "barrier_filter_query_v1": _lower_query_filtered_barrier_filter,
        "barrier_filter_continuation_v1": _lower_continuation_filtered_barrier_filter,
        "barrier_filter_inline_v1": _lower_inline_barrier_filter,
        "safe_predicate_injection_v1": _lower_safe_predicate_injection,
        "native_pg_rls_v1": _lower_native_pg_rls,
        "ordinary_first_exact_check_v1": _lower_ordinary_first_exact_check,
        "auth_view_scan_v1": _lower_auth_view_scan,
        "auth_index_enum_v1": _lower_auth_index_enum,
        "auth_index_semijoin_v1": _lower_auth_index_semijoin,
        "strong_auth_index_keyed_v1": _lower_strong_auth_index_keyed,
        "auth_index_keyed_semijoin_v1": _lower_auth_index_keyed_semijoin,
        "mav_scan_v1": _lower_mav_scan,
        "guard_candidate_plus_residual_v1": _lower_guard_candidate,
        "hybrid_intersect_v1": _lower_hybrid_intersect,
    }
)


def _scan_protected(node: ScanProtected, ctx: EmitContext, namespace: str) -> SQLFragment:
    try:
        definition = template_definition(node.template_slot)
    except KeyError:
        definition = None
    if definition is not None and definition.execution_class == "diagnostic_only":
        if not ctx.allow_diagnostic_lowering:
            raise TemplateLoweringError(
                "diagnostic protected template requires explicit diagnostic lowering authority: "
                f"{node.template_slot}"
            )
        return _lower_diagnostic_only_scan(node, ctx, namespace)
    lowerer = PROTECTED_SCAN_LOWERERS.get(node.template_slot)
    if lowerer is None:
        raise TemplateLoweringError(
            "no executable lowering registered for protected template: "
            f"{node.template_slot}"
        )
    return lowerer(node, ctx, namespace)


def _emit(node: PlanNode, ctx: EmitContext, namespace: str = "") -> SQLFragment:
    if isinstance(node, ScanProtected):
        return _scan_protected(node, ctx, namespace)
    if isinstance(node, ScanOrdinary):
        alias = _ident("o")
        return SQLFragment(
            body=f"SELECT {alias}.* FROM {_qualified_relation(ctx.schema, node.rel)} {alias}"
        )
    if isinstance(node, Select):
        source = _emit(node.source, ctx, namespace)
        return _combine(
            f"SELECT * FROM {_subquery(source, 'sel')} WHERE {node.pred}",
            source,
        )
    if isinstance(node, Project):
        source = _emit(node.source, ctx, namespace)
        columns = tuple(node.visible_A) + tuple(node.hidden_H)
        if not columns:
            projection = "*"
        else:
            projection = ", ".join(f"proj.{_ident(column)}" for column in columns)
        return _combine(
            f"SELECT {projection} FROM {_subquery(source, 'proj')}",
            source,
        )
    if isinstance(node, RCheck):
        source = _emit(node.source, ctx, namespace)
        predicate = ctx.residual_predicate_for(
            node.residual_id,
            occurrence_id=_single_protected_occurrence_id(node.source),
        )
        return _combine(
            f"SELECT * FROM {_subquery(source, 'rcheck')} WHERE {predicate}",
            source,
        )
    if isinstance(node, BarrierEnforce):
        source = _emit(node.source, ctx, namespace)
        cte = _cte_name("barrier", namespace or "enforce")
        return _combine(
            f"SELECT * FROM {cte}",
            source,
            ctes=(f"{cte} AS MATERIALIZED ({source.body})",),
        )
    if isinstance(node, ValidationGate):
        source = _emit(node.source, ctx, namespace)
        expected = ctx.artifact_expectations.get(node.artifact_id, {})
        if expected.__class__ is StrictArtifactExpectation:
            expected = list(expected.dependency_rows())
        statement = (
            "SELECT public.caprls_assert_artifact_valid("
            f"{_literal(node.artifact_id)}, {_jsonb_literal(expected)})"
        )
        return _combine(
            source.body,
            source,
            validation_statements=(statement,),
        )
    if isinstance(node, SortEnforce):
        source = _emit(node.source, ctx, namespace)
        keys = ", ".join(f"sorted.{_ident(key)}" for key in node.keys)
        return _combine(
            f"SELECT * FROM {_subquery(source, 'sorted')} ORDER BY {keys}",
            source,
        )
    if isinstance(node, Materialize):
        source = _emit(node.source, ctx, namespace)
        cte = _cte_name("mat", namespace or "node")
        return _combine(
            f"SELECT * FROM {cte}",
            source,
            ctes=(f"{cte} AS MATERIALIZED ({source.body})",),
        )
    if isinstance(node, Boundary):
        source = _emit(node.source, ctx, namespace)
        return _combine(
            f"SELECT * FROM {_subquery(source, 'boundary')} /* boundary:{node.kind} */",
            source,
        )
    if isinstance(node, DuplicateCollapse):
        source = _emit(node.source, ctx, namespace)
        return _combine(
            f"SELECT DISTINCT * FROM {_subquery(source, 'dedup')}",
            source,
        )
    if isinstance(node, UnsafeExpr):
        source = _emit(node.source, ctx, namespace)
        cte = _cte_name("unsafe", namespace or node.expr_label)
        event = _literal(ctx.unsafe_param_for(node.expr_label, "event", "caprls"))
        query_id = _literal(ctx.unsafe_param_for(node.expr_label, "query_id", "ir_emit"))
        label = _literal(ctx.unsafe_param_for(node.expr_label, "label", node.expr_label))
        occurrence_id = _literal(ctx.unsafe_param_for(node.expr_label, "occurrence_id", "occ"))
        rid_expr = str(ctx.unsafe_param_for(node.expr_label, "rid_expr", "unsafe_src.__rid"))
        secret_expr = str(ctx.unsafe_param_for(node.expr_label, "secret_expr", "''"))
        unsafe_call = (
            f"public.unsafe_log({event}, {query_id}, {label}, {occurrence_id}, "
            f"{rid_expr}, {secret_expr})"
        )
        return _combine(
            f"SELECT * FROM {cte}",
            source,
            ctes=(
                f"{cte} AS MATERIALIZED ("
                f"SELECT unsafe_src.* FROM {_subquery(source, 'unsafe_src')} "
                f"WHERE {unsafe_call})",
            ),
        )
    if isinstance(node, InnerJoin):
        left = _emit(node.left, ctx, _child_namespace(namespace, "left"))
        right = _emit(node.right, ctx, _child_namespace(namespace, "right"))
        theta = node.theta or "TRUE"
        return _combine(
            f"SELECT * FROM {_subquery(left, 'left_rel')} "
            f"JOIN {_subquery(right, 'right_rel')} ON {theta}",
            left,
            right,
        )
    if isinstance(node, UnionTagged):
        if not node.branches:
            raise ValueError("UnionTagged requires at least one branch")
        fragments = tuple(
            _emit(branch, ctx, _child_namespace(namespace, f"{node.branch_tag}{index}"))
            for index, branch in enumerate(node.branches)
        )
        selects = []
        tag_col = _ident(node.branch_tag)
        for index, fragment in enumerate(fragments):
            alias = f"branch_{index}"
            selects.append(
                f"SELECT {alias}.*, {_literal(f'{node.branch_tag}{index}')} AS {tag_col} "
                f"FROM {_subquery(fragment, alias)}"
            )
        return _combine("\nUNION ALL\n".join(selects), *fragments)
    if isinstance(node, Root):
        return _emit(node.source, ctx, namespace)
    raise TypeError(f"unsupported IR node: {node!r}")
