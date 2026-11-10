"""Immutable identity objects for the CAPRLS execution boundary.

This module deliberately does *not* execute SQL.  It creates the only object
that a future runner may bind: a frozen full SQL body, typed parameter list,
and session contract.  The current finite-fragment normalizer is explicitly a
controlled identity normalizer, not a theorem about arbitrary PostgreSQL AST
equivalence; unsupported SQL must therefore retain exact-text identity.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import weakref
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, NamedTuple, Protocol


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CORE_MARKER = "{{CORE_SQL}}"
_TYPE_STATE_TOKEN = object()
# Identity—not dataclass equality—records the exact conditional object minted
# by the verified-replay bridge.  A weak registry keeps this request-local
# provenance from becoming a persistent certificate cache and prevents
# ``dataclasses.replace`` from copying a static-replay capability into a new
# runtime-eligible object.
_VERIFIED_CONDITIONAL_PLANS: dict[
    int, weakref.ReferenceType["ConditionallyCheckedPlan"]
] = {}


class ExecutionIdentityError(ValueError):
    """Raised when a runner body does not exactly match a checked draft."""


class _TransactionAuthorizationCapability:
    """Opaque, non-serializable authority for one live transaction adapter.

    This is deliberately not part of an execution identity digest.  It is a
    process-local capability checked by the runner boundary, so a caller can
    inspect or copy an ``AuthorizedExecution`` for reporting without being
    able to turn an arbitrary type-state object into an executable request.
    """

    __slots__ = ("owner", "nonce")

    def __init__(self, owner: object, token: object) -> None:
        if token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError("transaction capability must be minted internally")
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "nonce", object())

    def __setattr__(self, name: str, value: object) -> None:
        raise ExecutionIdentityError("transaction authorization capability is immutable")


class _StaticReplayCapability:
    """Opaque provenance attached only after a successful certificate replay.

    A ``ConditionallyCheckedPlan`` is intentionally useful as an immutable
    report object, so its public compatibility factory can still construct a
    detached instance.  Only the private factory below attaches this
    capability.  The runtime transition refuses a detached instance before
    issuing plain EXPLAIN, which prevents an ordinary direct factory chain
    from laundering a self-asserted certificate into an execution request.
    """

    __slots__ = (
        "draft_identity_digest",
        "static_certificate_digest",
        "conditional_sigma_digest",
        "pending_dynamic_obligations_digest",
        "nonce",
    )

    def __init__(
        self,
        *,
        draft_identity_digest: str,
        static_certificate_digest: str,
        conditional_sigma_digest: str,
        pending_dynamic_obligations_digest: str,
        token: object,
    ) -> None:
        if token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError("static replay capability must be minted internally")
        object.__setattr__(self, "draft_identity_digest", draft_identity_digest)
        object.__setattr__(self, "static_certificate_digest", static_certificate_digest)
        object.__setattr__(self, "conditional_sigma_digest", conditional_sigma_digest)
        object.__setattr__(
            self,
            "pending_dynamic_obligations_digest",
            pending_dynamic_obligations_digest,
        )
        object.__setattr__(self, "nonce", object())

    def __setattr__(self, name: str, value: object) -> None:
        raise ExecutionIdentityError("static replay capability is immutable")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_digest(value: str, label: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise ExecutionIdentityError(f"{label} must be a sha256 digest")


_ARTIFACT_DYNAMIC_KINDS = frozenset(
    {"artifact_freshness", "artifact_context", "artifact_toctou"}
)
_ARTIFACT_DYNAMIC_RECIPE_SCHEMA = "caprls_artifact_dynamic_recipe"
_ARTIFACT_DYNAMIC_RECIPE_VERSION = 2
_ARTIFACT_DYNAMIC_RECIPE_FIELDS = frozenset(
    {
        "schema",
        "version",
        "artifact_id",
        "expected_dependency_digest",
        "expected_dependency_rows",
        "component_bindings_digest",
        "component_bindings",
        "gate_path",
        "occurrence_id",
        "template_id",
        "required_check_kinds",
        "kind",
        "subject_digest",
        "validator_version",
        "gamma_snapshot_id",
        "gamma_snapshot_digest",
        "fact_id",
    }
)
_ARTIFACT_COMPONENT_DEP_KINDS: Mapping[str, frozenset[str]] = MappingProxyType(
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
_ARTIFACT_DEPENDENCY_FIELDS = frozenset(
    {"dep_kind", "dep_name", "version_at_build"}
)
_ARTIFACT_COMPONENT_FIELDS = frozenset({"component", "dependencies"})
_ARTIFACT_DEPENDENCY_REF_FIELDS = frozenset({"dep_kind", "dep_name"})


def _freeze_recipe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_recipe_value(value[key]) for key in sorted(value, key=str)}
        )
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_recipe_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_recipe_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ExecutionIdentityError(
        f"dynamic validation recipe contains unsupported value: {type(value).__name__}"
    )


def _require_exact_artifact_recipe_keys(value: Any) -> None:
    """Reject artifact recipe keys before the generic compatibility normalizer."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if key.__class__ is not str:
                raise ExecutionIdentityError(
                    "artifact dynamic recipe mapping keys must be exact strings"
                )
            _require_exact_artifact_recipe_keys(item)
        return
    if isinstance(value, (tuple, list)):
        for item in value:
            _require_exact_artifact_recipe_keys(item)


def _thaw_recipe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_recipe_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_recipe_value(item) for item in value]
    if isinstance(value, frozenset):
        return sorted((_thaw_recipe_value(item) for item in value), key=_canonical_json)
    return value


def _canonical_recipe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical_recipe_value(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, tuple):
        return [_canonical_recipe_value(item) for item in value]
    if isinstance(value, frozenset):
        return sorted((_canonical_recipe_value(item) for item in value), key=_canonical_json)
    return value


def canonical_dynamic_recipe_digest(recipe_payload: Mapping[str, Any]) -> str:
    """Return the one canonical digest for an immutable H2 recipe payload."""

    if not isinstance(recipe_payload, Mapping):
        raise ExecutionIdentityError("dynamic validation recipe payload must be a mapping")
    frozen = _freeze_recipe_value(recipe_payload)
    return _digest(_canonical_json(_canonical_recipe_value(frozen)))


def _validate_artifact_recipe(
    *,
    kind: str,
    subject_digest: str,
    validator_version: str,
    recipe_payload: Mapping[str, Any],
) -> None:
    if kind not in _ARTIFACT_DYNAMIC_KINDS:
        return
    actual_fields = frozenset(recipe_payload)
    if actual_fields != _ARTIFACT_DYNAMIC_RECIPE_FIELDS:
        missing = tuple(sorted(_ARTIFACT_DYNAMIC_RECIPE_FIELDS - actual_fields))
        unknown = tuple(sorted(actual_fields - _ARTIFACT_DYNAMIC_RECIPE_FIELDS))
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise ExecutionIdentityError(
            "artifact dynamic recipe fields are not exact: " + "; ".join(details)
        )
    if (
        recipe_payload["schema"].__class__ is not str
        or recipe_payload["schema"] != _ARTIFACT_DYNAMIC_RECIPE_SCHEMA
        or recipe_payload["version"].__class__ is not int
        or recipe_payload["version"] != _ARTIFACT_DYNAMIC_RECIPE_VERSION
    ):
        raise ExecutionIdentityError("artifact dynamic recipe schema/version is unsupported")
    artifact_id = recipe_payload["artifact_id"]
    if artifact_id.__class__ is not str or not artifact_id:
        raise ExecutionIdentityError("artifact dynamic recipe artifact_id is invalid")
    if subject_digest != artifact_id:
        raise ExecutionIdentityError("artifact dynamic recipe subject does not match artifact_id")
    identity_fields = {
        "kind": kind,
        "subject_digest": subject_digest,
        "validator_version": validator_version,
    }
    for key, expected in identity_fields.items():
        if recipe_payload[key].__class__ is not str or recipe_payload[key] != expected:
            raise ExecutionIdentityError(
                f"artifact dynamic recipe {key} does not match obligation identity"
            )
    for key in ("occurrence_id", "template_id", "gamma_snapshot_id"):
        if recipe_payload[key].__class__ is not str or not recipe_payload[key]:
            raise ExecutionIdentityError(f"artifact dynamic recipe {key} is invalid")
    if recipe_payload["fact_id"].__class__ is not str:
        raise ExecutionIdentityError("artifact dynamic recipe fact_id is invalid")
    gamma_digest = recipe_payload["gamma_snapshot_digest"]
    if gamma_digest.__class__ is not str:
        raise ExecutionIdentityError(
            "artifact dynamic recipe gamma_snapshot_digest is invalid"
        )
    _require_digest(gamma_digest, "artifact dynamic recipe gamma_snapshot_digest")
    gate_path = recipe_payload["gate_path"]
    if (
        gate_path.__class__ is not tuple
        or not gate_path
        or any(item.__class__ is not str or not item for item in gate_path)
    ):
        raise ExecutionIdentityError("artifact dynamic recipe gate_path is invalid")
    required_kinds = recipe_payload["required_check_kinds"]
    if required_kinds != tuple(sorted(_ARTIFACT_DYNAMIC_KINDS)):
        raise ExecutionIdentityError("artifact dynamic recipe required_check_kinds is invalid")

    dependency_rows = recipe_payload["expected_dependency_rows"]
    if dependency_rows.__class__ is not tuple or not dependency_rows:
        raise ExecutionIdentityError(
            "artifact dynamic recipe requires nonempty dependency rows"
        )
    dependency_identities: list[tuple[str, str]] = []
    for row in dependency_rows:
        if not isinstance(row, Mapping) or frozenset(row) != _ARTIFACT_DEPENDENCY_FIELDS:
            raise ExecutionIdentityError(
                "artifact dynamic recipe dependency row fields are not exact"
            )
        dep_kind = row["dep_kind"]
        dep_name = row["dep_name"]
        version_at_build = row["version_at_build"]
        if (
            dep_kind.__class__ is not str
            or not dep_kind
            or dep_name.__class__ is not str
            or not dep_name
        ):
            raise ExecutionIdentityError(
                "artifact dynamic recipe dependency identity is invalid"
            )
        if version_at_build.__class__ is not int or version_at_build < 0:
            raise ExecutionIdentityError(
                "artifact dynamic recipe dependency version is invalid"
            )
        dependency_identities.append((dep_kind, dep_name))
    if dependency_identities != sorted(dependency_identities):
        raise ExecutionIdentityError(
            "artifact dynamic recipe dependency rows are not canonical"
        )
    if len(set(dependency_identities)) != len(dependency_identities):
        raise ExecutionIdentityError(
            "artifact dynamic recipe dependency identities are not unique"
        )
    expected_digest = recipe_payload["expected_dependency_digest"]
    if expected_digest.__class__ is not str:
        raise ExecutionIdentityError(
            "artifact dynamic recipe expected_dependency_digest is invalid"
        )
    _require_digest(
        expected_digest,
        "artifact dynamic recipe expected_dependency_digest",
    )
    if expected_digest != canonical_dynamic_recipe_digest(
        {"dependency_rows": dependency_rows}
    ):
        raise ExecutionIdentityError(
            "artifact dynamic recipe dependency digest does not match dependency rows"
        )

    component_bindings = recipe_payload["component_bindings"]
    if component_bindings.__class__ is not tuple:
        raise ExecutionIdentityError(
            "artifact dynamic recipe component_bindings is invalid"
        )
    components: list[str] = []
    consumed: set[tuple[str, str]] = set()
    known = set(dependency_identities)
    for binding in component_bindings:
        if not isinstance(binding, Mapping) or frozenset(binding) != _ARTIFACT_COMPONENT_FIELDS:
            raise ExecutionIdentityError(
                "artifact dynamic recipe component binding fields are not exact"
            )
        component = binding["component"]
        if (
            component.__class__ is not str
            or component not in _ARTIFACT_COMPONENT_DEP_KINDS
        ):
            raise ExecutionIdentityError(
                "artifact dynamic recipe component binding is unknown"
            )
        references = binding["dependencies"]
        if references.__class__ is not tuple or not references:
            raise ExecutionIdentityError(
                "artifact dynamic recipe component binding is empty"
            )
        normalized_references: list[tuple[str, str]] = []
        for reference in references:
            if (
                not isinstance(reference, Mapping)
                or frozenset(reference) != _ARTIFACT_DEPENDENCY_REF_FIELDS
            ):
                raise ExecutionIdentityError(
                    "artifact dynamic recipe dependency reference fields are not exact"
                )
            dep_kind = reference["dep_kind"]
            dep_name = reference["dep_name"]
            if (
                dep_kind.__class__ is not str
                or not dep_kind
                or dep_name.__class__ is not str
                or not dep_name
            ):
                raise ExecutionIdentityError(
                    "artifact dynamic recipe dependency reference is invalid"
                )
            identity = (dep_kind, dep_name)
            if dep_kind not in _ARTIFACT_COMPONENT_DEP_KINDS[component]:
                raise ExecutionIdentityError(
                    "artifact dynamic recipe component uses an unsupported dependency kind"
                )
            if identity not in known:
                raise ExecutionIdentityError(
                    "artifact dynamic recipe component references an unknown dependency"
                )
            normalized_references.append(identity)
            consumed.add(identity)
        if normalized_references != sorted(normalized_references):
            raise ExecutionIdentityError(
                "artifact dynamic recipe dependency references are not canonical"
            )
        if len(set(normalized_references)) != len(normalized_references):
            raise ExecutionIdentityError(
                "artifact dynamic recipe component repeats a dependency reference"
            )
        components.append(component)
    if components != sorted(_ARTIFACT_COMPONENT_DEP_KINDS):
        raise ExecutionIdentityError(
            "artifact dynamic recipe must bind exactly all H2 components canonically"
        )
    if consumed != known:
        raise ExecutionIdentityError(
            "artifact dynamic recipe contains an unconsumed dependency"
        )
    bindings_digest = recipe_payload["component_bindings_digest"]
    if bindings_digest.__class__ is not str:
        raise ExecutionIdentityError(
            "artifact dynamic recipe component_bindings_digest is invalid"
        )
    _require_digest(
        bindings_digest,
        "artifact dynamic recipe component_bindings_digest",
    )
    if bindings_digest != canonical_dynamic_recipe_digest(
        {"component_bindings": component_bindings}
    ):
        raise ExecutionIdentityError(
            "artifact dynamic recipe component binding digest does not match bindings"
        )


@dataclass(frozen=True)
class DynamicObligation:
    """Immutable, trial-local H2 validation recipe.

    The recipe is carried from certificate replay through every execution
    type-state transition.  An obligation *ID* alone is deliberately
    insufficient: a validator receipt must be bound to the artifact/policy
    subject, validator version, and exact revalidation recipe that planning
    left unresolved.
    """

    obligation_id: str
    kind: str
    subject_digest: str
    validator_version: str
    recipe_digest: str
    recipe_payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (
                self.obligation_id,
                self.kind,
                self.subject_digest,
                self.validator_version,
            )
        ):
            raise ExecutionIdentityError("dynamic obligation requires complete validator identity")
        if not isinstance(self.recipe_payload, Mapping):
            raise ExecutionIdentityError("dynamic obligation recipe_payload must be a mapping")
        if self.kind in _ARTIFACT_DYNAMIC_KINDS:
            _require_exact_artifact_recipe_keys(self.recipe_payload)
        frozen_payload = _freeze_recipe_value(self.recipe_payload)
        object.__setattr__(self, "recipe_payload", frozen_payload)
        # Existing typed Gamma contracts use this field as a canonical subject
        # identifier for both hash-shaped policy subjects and catalog artifact
        # IDs.  Its exact value is carried and matched end-to-end; requiring a
        # sha256 spelling here would incorrectly reject valid artifact/view
        # contracts before their validator can bind the subject.
        _require_digest(self.recipe_digest, "dynamic obligation recipe_digest")
        if frozen_payload and self.recipe_digest != canonical_dynamic_recipe_digest(frozen_payload):
            raise ExecutionIdentityError(
                "dynamic obligation recipe_digest does not match recipe_payload"
            )
        _validate_artifact_recipe(
            kind=self.kind,
            subject_digest=self.subject_digest,
            validator_version=self.validator_version,
            recipe_payload=frozen_payload,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "obligation_id": self.obligation_id,
            "kind": self.kind,
            "subject_digest": self.subject_digest,
            "validator_version": self.validator_version,
            "recipe_digest": self.recipe_digest,
            "recipe_payload": _thaw_recipe_value(self.recipe_payload),
        }

    @property
    def identity_digest(self) -> str:
        return _digest(_canonical_json(self.to_dict()))


def _normalize_dynamic_obligations(
    obligations: tuple[DynamicObligation, ...] | list[DynamicObligation],
) -> tuple[DynamicObligation, ...]:
    normalized = tuple(obligations)
    if any(not isinstance(item, DynamicObligation) for item in normalized):
        raise ExecutionIdentityError("pending dynamic obligations must be DynamicObligation values")
    if any(not item.obligation_id for item in normalized):
        raise ExecutionIdentityError("pending dynamic obligation IDs must be nonempty")
    if len({item.obligation_id for item in normalized}) != len(normalized):
        raise ExecutionIdentityError("pending dynamic obligation IDs must be unique")
    return tuple(sorted(normalized, key=lambda item: item.obligation_id))


def _dynamic_obligations_digest(obligations: tuple[DynamicObligation, ...]) -> str:
    return _digest(_canonical_json([item.to_dict() for item in obligations]))


def canonical_sql_fragment_digest(sql: str) -> str:
    """Stable finite-fragment normalization used only as a secondary anchor.

    Exact SQL digest remains authoritative.  The normalized digest gives the
    certificate/replay layer a deterministic representation for controlled
    templates without pretending that whitespace normalization proves general
    SQL AST equivalence.
    """

    normalized = re.sub(r"\s+", " ", sql.strip())
    return _digest(normalized)


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): value[key] for key in sorted(value)})


def _canonical_parameter_value(value: Any) -> Any:
    """Render the supported typed-value fragment without alias-dependent state."""

    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        # JSON permits non-finite spellings inconsistently across consumers;
        # make their identity explicit rather than silently normalizing them.
        return value if math.isfinite(value) else {"__float__": repr(value)}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, Mapping):
        pairs = [
            (_canonical_parameter_value(key), _canonical_parameter_value(item))
            for key, item in value.items()
        ]
        return {
            "__mapping__": sorted(
                pairs,
                key=lambda item: _canonical_json(item[0]),
            )
        }
    if isinstance(value, (tuple, list)):
        return {
            "__sequence_type__": type(value).__name__,
            "items": [_canonical_parameter_value(item) for item in value],
        }
    if isinstance(value, (frozenset, set)):
        items = [_canonical_parameter_value(item) for item in value]
        return {
            "__set_type__": type(value).__name__,
            "items": sorted(items, key=_canonical_json),
        }
    raise ExecutionIdentityError(
        f"unsupported mutable or non-canonical bound parameter value: {type(value).__name__}"
    )


def _freeze_parameter_value(value: Any) -> Any:
    """Recursively own parameter values before any authorization transition.

    A frozen dataclass does not freeze a list/dict stored in it.  Retaining
    those containers allowed a malicious runner to mutate a parameter after
    the last identity check but before its own body counter/SQL call.  The
    runtime adapter receives only recursively immutable values now.
    """

    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, Mapping):
        frozen: dict[Any, Any] = {}
        for key, item in value.items():
            frozen[_freeze_parameter_value(key)] = _freeze_parameter_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_parameter_value(item) for item in value)
    if isinstance(value, (frozenset, set)):
        return frozenset(_freeze_parameter_value(item) for item in value)
    raise ExecutionIdentityError(
        f"unsupported mutable bound parameter value: {type(value).__name__}"
    )


@dataclass(frozen=True)
class BoundParameter:
    """One immutable, typed bind parameter; no interpolation is authorized."""

    name: str
    postgres_type: str
    value: Any
    _value_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _PARAMETER_NAME_RE.fullmatch(self.name):
            raise ExecutionIdentityError(f"unsafe parameter name: {self.name!r}")
        if not self.postgres_type:
            raise ExecutionIdentityError("bound parameter postgres_type is required")
        try:
            snapshot = deepcopy(self.value)
        except Exception as exc:
            raise ExecutionIdentityError(
                f"bound parameter value cannot be snapshotted: {type(self.value).__name__}"
            ) from exc
        frozen_value = _freeze_parameter_value(snapshot)
        canonical = _canonical_parameter_value(frozen_value)
        object.__setattr__(self, "value", frozen_value)
        object.__setattr__(self, "_value_digest", _digest(_canonical_json(canonical)))

    def _assert_value_unchanged(self) -> None:
        current = _digest(_canonical_json(_canonical_parameter_value(self.value)))
        if current != self._value_digest:
            raise ExecutionIdentityError("bound parameter value mutated after construction")

    def _identity_payload(self) -> dict[str, Any]:
        self._assert_value_unchanged()
        return {
            "name": self.name,
            "postgres_type": self.postgres_type,
            "value": _canonical_parameter_value(self.value),
        }

    @property
    def digest(self) -> str:
        return _digest(_canonical_json(self._identity_payload()))


@dataclass(frozen=True)
class SessionContract:
    """Session facts that affect SQL meaning or authorization."""

    role: str
    search_path: tuple[str, ...]
    gucs: Mapping[str, str] = field(default_factory=dict)
    transaction_isolation: str = "repeatable read"
    read_only: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "search_path", tuple(str(item) for item in self.search_path))
        object.__setattr__(self, "gucs", _freeze_mapping(self.gucs))
        if not self.role:
            raise ExecutionIdentityError("session contract requires an effective role")
        if not self.search_path:
            raise ExecutionIdentityError("session contract requires an explicit search_path")
        if self.transaction_isolation.lower() != "repeatable read":
            raise ExecutionIdentityError(
                "authorized CAPRLS execution requires repeatable read isolation"
            )

    @property
    def digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "role": self.role,
                    "search_path": self.search_path,
                    "gucs": dict(self.gucs),
                    "transaction_isolation": self.transaction_isolation.lower(),
                    "read_only": self.read_only,
                }
            )
        )


class ContinuationDefinition(NamedTuple):
    """One reviewed, finite continuation shape eligible for execution.

    This is intentionally an exact-template registry rather than a SQL
    sanitizer.  Without a PostgreSQL-compatible, version-locked parser we
    cannot prove that an arbitrary caller-provided wrapper preserves the
    protected core: even a single-statement wrapper can add an unrelated scan
    or union.  New shapes therefore require an explicit source-controlled
    definition and tests before they may reach :class:`ExecutableDraft`.
    """

    continuation_id: str
    template: str
    wrapper_kind: str

    def assert_valid(self) -> None:
        """Recheck fields because frozen dataclasses can be bypassed in-process."""

        if (
            type(self.continuation_id) is not str
            or type(self.template) is not str
            or type(self.wrapper_kind) is not str
        ):
            raise ExecutionIdentityError(
                "approved continuation definition fields must be exact str values"
            )
        if not self.continuation_id or not self.wrapper_kind:
            raise ExecutionIdentityError(
                "approved continuation definition requires ID and wrapper kind"
            )
        if self.template.count(_CORE_MARKER) != 1:
            raise ExecutionIdentityError(
                "approved continuation definition must contain exactly one {{CORE_SQL}} marker"
            )
        if ";" in self.template or "\\" in self.template:
            raise ExecutionIdentityError(
                "approved continuation definition cannot contain semicolons or psql directives"
            )

    @property
    def digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "continuation_id": self.continuation_id,
                    "template": self.template,
                    "wrapper_kind": self.wrapper_kind,
                }
            )
        )


# The complete executable continuation portfolio for the finite fragment.
# Identity aliases are retained only for existing fixture/adapter identities;
# their exact template is still frozen.  The two aggregate wrappers are the
# already-used controlled count shapes and introduce no caller-controlled SQL
# hole beyond the one protected core marker.
APPROVED_CONTINUATION_DEFINITIONS: Mapping[str, ContinuationDefinition] = MappingProxyType(
    {
        "identity-continuation-v1": ContinuationDefinition(
            "identity-continuation-v1", _CORE_MARKER, "identity"
        ),
        "identity-v1": ContinuationDefinition("identity-v1", _CORE_MARKER, "identity"),
        "identity-v2": ContinuationDefinition("identity-v2", _CORE_MARKER, "identity"),
        "strict-identity-v1": ContinuationDefinition(
            "strict-identity-v1", _CORE_MARKER, "identity"
        ),
        "replay-binding-v1": ContinuationDefinition(
            "replay-binding-v1", _CORE_MARKER, "identity"
        ),
        "runtime-count-v1": ContinuationDefinition(
            "runtime-count-v1",
            "WITH q AS ({{CORE_SQL}}) SELECT count(*) FROM q",
            "count_aggregate",
        ),
        "count-wrapper-v1": ContinuationDefinition(
            "count-wrapper-v1",
            "WITH body AS MATERIALIZED ({{CORE_SQL}}) SELECT count(*) FROM body",
            "count_aggregate",
        ),
    }
)

# Fail at import time if a source-controlled registry entry itself is malformed.
# ``ContinuationDefinition`` is a NamedTuple (rather than a merely frozen
# dataclass), so neither direct assignment nor ``object.__setattr__`` can
# mutate a reviewed definition after this validation.
for _approved_continuation_definition in APPROVED_CONTINUATION_DEFINITIONS.values():
    _approved_continuation_definition.assert_valid()
del _approved_continuation_definition


def approved_continuation_definitions() -> tuple[ContinuationDefinition, ...]:
    """Expose the frozen registry for capability audits and tests."""

    return tuple(
        APPROVED_CONTINUATION_DEFINITIONS[key]
        for key in sorted(APPROVED_CONTINUATION_DEFINITIONS)
    )


@dataclass(frozen=True)
class ContinuationTemplate:
    """A candidate continuation wrapper around a lowered core SQL fragment.

    Constructing an object remains possible for diagnostics and strict
    preflight error reporting.  Rendering it, and therefore constructing an
    executable draft, requires an exact match to the frozen approved
    definition registry above.
    """

    continuation_id: str
    template: str = _CORE_MARKER

    def __post_init__(self) -> None:
        if type(self.continuation_id) is not str or type(self.template) is not str:
            raise ExecutionIdentityError(
                "continuation_id and template must be exact str values"
            )
        if not self.continuation_id:
            raise ExecutionIdentityError("continuation_id is required")
        if self.template.count(_CORE_MARKER) != 1:
            raise ExecutionIdentityError(
                "continuation template must contain exactly one {{CORE_SQL}} marker"
            )
        # Until a version-locked PostgreSQL parser is available, continuations
        # are a deliberately tiny single-statement language.  A semicolon or
        # psql meta-command in the wrapper could otherwise append an unrelated
        # statement while preserving the protected-core digest.
        if ";" in self.template or "\\" in self.template:
            raise ExecutionIdentityError(
                "controlled continuation template cannot contain semicolons or psql directives"
            )
        definition = APPROVED_CONTINUATION_DEFINITIONS.get(self.continuation_id)
        if definition is not None and definition.template != self.template:
            raise ExecutionIdentityError(
                "continuation_id does not match approved frozen continuation definition"
            )

    @property
    def approved_definition(self) -> ContinuationDefinition:
        if type(self.continuation_id) is not str or type(self.template) is not str:
            raise ExecutionIdentityError(
                "continuation is not an approved frozen continuation definition"
            )
        definition = APPROVED_CONTINUATION_DEFINITIONS.get(self.continuation_id)
        if type(definition) is not ContinuationDefinition:
            raise ExecutionIdentityError(
                "continuation is not an approved frozen continuation definition"
            )
        try:
            definition.assert_valid()
        except ExecutionIdentityError as exc:
            raise ExecutionIdentityError(
                "continuation is not an approved frozen continuation definition"
            ) from exc
        if (
            str.__eq__(definition.continuation_id, self.continuation_id) is not True
            or str.__eq__(definition.template, self.template) is not True
        ):
            raise ExecutionIdentityError(
                "continuation is not an approved frozen continuation definition"
            )
        return definition

    @property
    def is_approved(self) -> bool:
        try:
            _ = self.approved_definition
        except ExecutionIdentityError:
            return False
        return True

    def assert_approved(self) -> None:
        """Reject non-reviewed wrapper structure before any SQL is rendered."""

        _ = self.approved_definition

    @property
    def digest(self) -> str:
        definition = self.approved_definition
        return _digest(
            _canonical_json(
                {
                    "continuation_id": self.continuation_id,
                    "template": self.template,
                    "approved_definition_digest": definition.digest,
                }
            )
        )

    def render(self, core_sql: str) -> str:
        return _render_approved_continuation(self, core_sql)


def _render_approved_continuation(
    continuation: ContinuationTemplate,
    core_sql: str,
) -> str:
    """Render through the exact approved definition, never dynamic dispatch.

    ``ExecutableDraft`` calls this helper directly.  Requiring the exact
    concrete class prevents a subclass from overriding ``render`` after the
    continuation passed its registry checks.
    """

    if type(continuation) is not ContinuationTemplate:
        raise ExecutionIdentityError(
            "executable SQL requires an exact ContinuationTemplate"
        )
    definition = continuation.approved_definition
    core = _normalize_controlled_core_sql(core_sql)
    # Both strings are exact built-ins after the checks above, so this cannot
    # invoke an attacker-controlled ``replace`` implementation.
    rendered = str.replace(definition.template, _CORE_MARKER, core) + ";"
    if rendered.count(";") != 1 or not rendered.endswith(";") or "\\" in rendered:
        raise ExecutionIdentityError("controlled continuation must render exactly one SQL statement")
    return rendered


def _normalize_controlled_core_sql(core_sql: str) -> str:
    """Accept one nonempty statement with at most one optional terminator.

    This finite fragment deliberately rejects every remaining semicolon
    (including semicolons inside literals) until a version-locked PostgreSQL
    parser is introduced.  In particular, do not use ``rstrip(';')`` here:
    it would silently accept ``SELECT 1;;`` by removing both terminators.
    """

    if type(core_sql) is not str:
        raise ExecutionIdentityError("core SQL must be an exact str value")
    stripped = core_sql.rstrip()
    if stripped.endswith(";"):
        stripped = stripped[:-1].rstrip()
    if not stripped:
        raise ExecutionIdentityError("core SQL cannot be empty")
    if ";" in stripped or "\\" in stripped:
        raise ExecutionIdentityError("controlled core SQL must be a single SQL statement")
    return stripped


IDENTITY_CONTINUATION = ContinuationTemplate("identity-continuation-v1")


@dataclass(frozen=True)
class SemanticContinuationScope:
    """Data binding for a core complete only under one semantic continuation.

    This value grants no admission or execution authority. A certificate must
    establish the proof/descriptor binding, and the bound-runner consumer must
    match the registered continuation. Generic core execution rejects it.
    """

    occurrence_id: str
    continuation_digest: str
    continuation_sql_digest: str
    result_contract_digest: str
    necessity_proof_digest: str
    descriptor_digest: str

    def __post_init__(self) -> None:
        self.assert_valid()

    def assert_valid(self) -> None:
        if type(self) is not SemanticContinuationScope:
            raise ExecutionIdentityError("semantic continuation scope must have its exact type")
        if type(self.occurrence_id) is not str or not self.occurrence_id:
            raise ExecutionIdentityError("semantic continuation scope requires an occurrence")
        for label in (
            "continuation_digest", "continuation_sql_digest", "result_contract_digest",
            "necessity_proof_digest", "descriptor_digest",
        ):
            value = getattr(self, label)
            if type(value) is not str:
                raise ExecutionIdentityError("semantic continuation scope has an invalid " + label)
            _require_digest(value, "semantic continuation scope " + label)

    def to_dict(self) -> dict[str, str]:
        self.assert_valid()
        return {
            "schema": "caprls_semantic_continuation_scope_v1",
            "occurrence_id": self.occurrence_id,
            "continuation_digest": self.continuation_digest,
            "continuation_sql_digest": self.continuation_sql_digest,
            "result_contract_digest": self.result_contract_digest,
            "necessity_proof_digest": self.necessity_proof_digest,
            "descriptor_digest": self.descriptor_digest,
        }

    @property
    def digest(self) -> str:
        return _digest(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class ExecutableDraft:
    """A non-executable, exact SQL body produced before static verification."""

    plan_id: str
    bound_ir_digest: str
    core_ast_digest: str
    continuation_ast_digest: str
    full_ast_digest: str
    exact_sql_digest: str
    core_sql: str
    sql_text: str
    typed_params: tuple[BoundParameter, ...]
    session_contract: SessionContract
    registry_version: str
    registry_digest: str
    continuation_id: str
    continuation: ContinuationTemplate
    _construction_token: object = field(repr=False, compare=False, default=None)
    continuation_scope: SemanticContinuationScope | None = None

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError(
                "ExecutableDraft must be created by from_core_sql, not a raw SQL constructor"
            )
        object.__setattr__(self, "typed_params", tuple(self.typed_params))
        if not self.plan_id or not self.registry_version or not self.continuation_id:
            raise ExecutionIdentityError("draft requires plan_id, registry_version, and continuation_id")
        if type(self.continuation) is not ContinuationTemplate:
            raise ExecutionIdentityError("draft requires an exact ContinuationTemplate")
        if (
            type(self.continuation_id) is not str
            or type(self.continuation.continuation_id) is not str
            or str.__eq__(self.continuation_id, self.continuation.continuation_id) is not True
        ):
            raise ExecutionIdentityError("draft continuation_id does not match continuation template")
        if type(self.core_sql) is not str or type(self.sql_text) is not str:
            raise ExecutionIdentityError("draft SQL fields must be exact str values")
        _ = _normalize_controlled_core_sql(self.core_sql)
        if any(not isinstance(parameter, BoundParameter) for parameter in self.typed_params):
            raise ExecutionIdentityError("typed_params must contain BoundParameter values")
        parameter_names = [parameter.name for parameter in self.typed_params]
        if len(parameter_names) != len(set(parameter_names)):
            raise ExecutionIdentityError("typed parameter names must be unique")
        referenced_parameters = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", self.sql_text))
        if referenced_parameters != set(parameter_names):
            raise ExecutionIdentityError(
                "controlled SQL parameter holes do not exactly match typed parameters"
            )
        if not isinstance(self.session_contract, SessionContract):
            raise ExecutionIdentityError("draft requires a typed SessionContract")
        self._assert_continuation_scope()
        for label, digest in (
            ("bound_ir_digest", self.bound_ir_digest),
            ("core_ast_digest", self.core_ast_digest),
            ("continuation_ast_digest", self.continuation_ast_digest),
            ("full_ast_digest", self.full_ast_digest),
            ("exact_sql_digest", self.exact_sql_digest),
            ("registry_digest", self.registry_digest),
        ):
            _require_digest(digest, label)
        if self.sql_text != _render_approved_continuation(self.continuation, self.core_sql):
            raise ExecutionIdentityError("draft full SQL is not compose(continuation, core_sql)")
        if self.core_ast_digest != canonical_sql_fragment_digest(self.core_sql):
            raise ExecutionIdentityError("draft core_ast_digest does not match core_sql")
        if self.continuation_ast_digest != self.continuation.digest:
            raise ExecutionIdentityError("draft continuation_ast_digest does not match continuation")
        if self.exact_sql_digest != _digest(self.sql_text):
            raise ExecutionIdentityError("draft exact_sql_digest does not match sql_text")
        if self.full_ast_digest != canonical_sql_fragment_digest(self.sql_text):
            raise ExecutionIdentityError("draft full_ast_digest does not match controlled SQL normalization")
        self.assert_identity_intact()

    @classmethod
    def from_core_sql(
        cls,
        *,
        plan_id: str,
        bound_ir_digest: str,
        core_sql: str,
        continuation: ContinuationTemplate,
        typed_params: tuple[BoundParameter, ...] = (),
        session_contract: SessionContract,
        registry_version: str,
        registry_digest: str,
        continuation_scope: SemanticContinuationScope | None = None,
    ) -> "ExecutableDraft":
        _require_digest(bound_ir_digest, "bound_ir_digest")
        if type(continuation) is not ContinuationTemplate:
            raise ExecutionIdentityError(
                "ExecutableDraft requires an exact ContinuationTemplate"
            )
        # Check approval explicitly at the executable boundary as well as in
        # ``render``.  This keeps a future alternate renderer from turning an
        # unapproved diagnostic wrapper into executable SQL by accident.
        continuation.assert_approved()
        sql_text = _render_approved_continuation(continuation, core_sql)
        return cls(
            plan_id=plan_id,
            bound_ir_digest=bound_ir_digest,
            core_ast_digest=canonical_sql_fragment_digest(core_sql),
            continuation_ast_digest=continuation.digest,
            full_ast_digest=canonical_sql_fragment_digest(sql_text),
            exact_sql_digest=_digest(sql_text),
            core_sql=core_sql,
            sql_text=sql_text,
            typed_params=typed_params,
            session_contract=session_contract,
            registry_version=registry_version,
            registry_digest=registry_digest,
            continuation_id=continuation.continuation_id,
            continuation=continuation,
            _construction_token=_TYPE_STATE_TOKEN,
            continuation_scope=continuation_scope,
        )

    def _assert_continuation_scope(self) -> None:
        if self.continuation_scope is not None:
            if type(self.continuation_scope) is not SemanticContinuationScope:
                raise ExecutionIdentityError("draft semantic continuation scope is malformed")
            SemanticContinuationScope.assert_valid(self.continuation_scope)

    @property
    def parameter_digest(self) -> str:
        return _digest(
            _canonical_json([parameter._identity_payload() for parameter in self.typed_params])
        )

    def assert_identity_intact(self) -> None:
        """Revalidate mutable-adjacent state before a physical transition."""

        # Frozen dataclasses prevent ordinary field replacement, but typed
        # parameter values may originate as nested containers.  Recompute the
        # protected identities at every callback/runner boundary so alias
        # mutation cannot change what PostgreSQL sees after verification.
        _ = self.parameter_digest
        self._assert_continuation_scope()
        if (
            type(self.continuation) is not ContinuationTemplate
            or type(self.continuation_id) is not str
            or type(self.continuation.continuation_id) is not str
            or str.__eq__(self.continuation_id, self.continuation.continuation_id)
            is not True
        ):
            raise ExecutionIdentityError(
                "draft continuation identity changed after construction"
            )
        try:
            current_continuation_digest = self.continuation.digest
        except ExecutionIdentityError as exc:
            raise ExecutionIdentityError(
                "draft continuation identity changed after construction"
            ) from exc
        if self.continuation_ast_digest != current_continuation_digest:
            raise ExecutionIdentityError(
                "draft continuation identity changed after construction"
            )
        if self.sql_text != _render_approved_continuation(self.continuation, self.core_sql):
            raise ExecutionIdentityError("draft full SQL changed after construction")
        if self.exact_sql_digest != _digest(self.sql_text):
            raise ExecutionIdentityError("draft exact SQL changed after construction")
        if self.core_ast_digest != canonical_sql_fragment_digest(self.core_sql):
            raise ExecutionIdentityError("draft core SQL changed after construction")
        if self.full_ast_digest != canonical_sql_fragment_digest(self.sql_text):
            raise ExecutionIdentityError("draft full SQL normalization changed after construction")

    @property
    def identity_digest(self) -> str:
        payload = {
            "plan_id": self.plan_id,
            "bound_ir_digest": self.bound_ir_digest,
            "core_ast_digest": self.core_ast_digest,
            "continuation_ast_digest": self.continuation_ast_digest,
            "full_ast_digest": self.full_ast_digest,
            "exact_sql_digest": self.exact_sql_digest,
            "parameter_digest": self.parameter_digest,
            "session_digest": self.session_contract.digest,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "continuation_id": self.continuation_id,
        }
        self._assert_continuation_scope()
        if self.continuation_scope is not None:
            payload["semantic_continuation_scope"] = self.continuation_scope.to_dict()
        return _digest(_canonical_json(payload))


@dataclass(frozen=True)
class RunnerBodyBinding:
    """Proof that a runner is about to use this draft's exact body/session."""

    draft: ExecutableDraft
    runner_sql_digest: str
    runner_parameter_digest: str
    runner_session_digest: str
    _construction_token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError("runner body binding must be minted from ExecutableDraft")
        if not isinstance(self.draft, ExecutableDraft):
            raise ExecutionIdentityError("runner body binding requires ExecutableDraft")
        self.draft.assert_identity_intact()
        if self.draft.continuation_scope is not None:
            raise ExecutionIdentityError(
                "generic core execution cannot discharge a semantic continuation scope"
            )
        if self.runner_sql_digest != self.draft.exact_sql_digest:
            raise ExecutionIdentityError("runner SQL does not match ExecutableDraft")
        if self.runner_parameter_digest != self.draft.parameter_digest:
            raise ExecutionIdentityError("runner parameters do not match ExecutableDraft")
        if self.runner_session_digest != self.draft.session_contract.digest:
            raise ExecutionIdentityError("runner session does not match ExecutableDraft")

    @property
    def identity_digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "draft_identity_digest": self.draft.identity_digest,
                    "runner_sql_digest": self.runner_sql_digest,
                    "runner_parameter_digest": self.runner_parameter_digest,
                    "runner_session_digest": self.runner_session_digest,
                }
            )
        )

    @property
    def sql_text(self) -> str:
        return self.draft.sql_text

    @property
    def typed_params(self) -> tuple[BoundParameter, ...]:
        return self.draft.typed_params

    @property
    def session_contract(self) -> SessionContract:
        return self.draft.session_contract


def bind_runner_body(
    draft: ExecutableDraft,
    *,
    sql_text: str,
    typed_params: tuple[BoundParameter, ...],
    session_contract: SessionContract,
) -> RunnerBodyBinding:
    """Fail closed unless a runner received the exact checked execution body."""

    draft.assert_identity_intact()
    if draft.continuation_scope is not None:
        raise ExecutionIdentityError(
            "generic core execution cannot discharge a semantic continuation scope"
        )
    return RunnerBodyBinding(
        draft=draft,
        runner_sql_digest=_digest(sql_text),
        runner_parameter_digest=_digest(
            _canonical_json(
                [parameter._identity_payload() for parameter in tuple(typed_params)]
            )
        ),
        runner_session_digest=session_contract.digest,
        _construction_token=_TYPE_STATE_TOKEN,
    )


# The following objects form the one-way execution type-state boundary.  They
# intentionally live next to ExecutableDraft so no runner needs to infer
# identity from a copied SQL string.  The private construction token is not a
# security boundary against malicious in-process code; it is a fail-closed API
# guard that prevents ordinary callers from skipping a required transition.


@dataclass(frozen=True)
class ConditionallyCheckedPlan:
    """A draft whose static certificate was replayed, but is not executable."""

    draft: ExecutableDraft
    static_certificate_digest: str
    conditional_sigma_digest: str
    pending_dynamic_obligations: tuple[DynamicObligation, ...] = ()
    _static_replay_capability: _StaticReplayCapability | None = field(
        repr=False,
        compare=False,
        default=None,
    )
    _construction_token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError(
                "ConditionallyCheckedPlan must be created by certificate replay"
            )
        if not isinstance(self.draft, ExecutableDraft):
            raise ExecutionIdentityError("conditional plan requires an ExecutableDraft")
        _require_digest(self.static_certificate_digest, "static_certificate_digest")
        _require_digest(self.conditional_sigma_digest, "conditional_sigma_digest")
        obligations = _normalize_dynamic_obligations(self.pending_dynamic_obligations)
        object.__setattr__(self, "pending_dynamic_obligations", obligations)
        capability = self._static_replay_capability
        if capability is not None:
            if not isinstance(capability, _StaticReplayCapability):
                raise ExecutionIdentityError("conditional plan has an invalid static replay capability")
            if (
                capability.draft_identity_digest != self.draft.identity_digest
                or capability.static_certificate_digest != self.static_certificate_digest
                or capability.conditional_sigma_digest != self.conditional_sigma_digest
                or capability.pending_dynamic_obligations_digest
                != _dynamic_obligations_digest(self.pending_dynamic_obligations)
            ):
                raise ExecutionIdentityError(
                    "conditional plan static replay capability does not match its immutable identity"
                )

    @property
    def identity_digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "draft": self.draft.identity_digest,
                    "static_certificate_digest": self.static_certificate_digest,
                    "conditional_sigma_digest": self.conditional_sigma_digest,
                    "pending_dynamic_obligations": [
                        item.to_dict() for item in self.pending_dynamic_obligations
                    ],
                }
            )
        )

    @property
    def pending_dynamic_obligation_ids(self) -> tuple[str, ...]:
        """Compatibility/readability view; runtime authorization uses full recipes."""

        return tuple(item.obligation_id for item in self.pending_dynamic_obligations)


def make_conditionally_checked_plan(
    *,
    draft: ExecutableDraft,
    static_certificate_digest: str,
    conditional_sigma_digest: str,
    pending_dynamic_obligations: tuple[DynamicObligation, ...] = (),
) -> ConditionallyCheckedPlan:
    """Create a detached conditional report object, never a runtime input.

    Compatibility callers may use this to represent a checked-looking state
    in tests, reports, or migration code.  It carries no static-replay
    provenance and is deliberately rejected by the runtime before plain
    EXPLAIN.  ``certificate_envelope`` uses the private verified-replay
    factory after it has authenticated the actual replay result.
    """

    return ConditionallyCheckedPlan(
        draft=draft,
        static_certificate_digest=static_certificate_digest,
        conditional_sigma_digest=conditional_sigma_digest,
        pending_dynamic_obligations=tuple(pending_dynamic_obligations),
        _static_replay_capability=None,
        _construction_token=_TYPE_STATE_TOKEN,
    )


def _make_conditionally_checked_plan_from_verified_replay(
    *,
    draft: ExecutableDraft,
    replay_draft_identity_digest: str,
    static_certificate_digest: str,
    conditional_sigma_digest: str,
    pending_dynamic_obligations: tuple[DynamicObligation, ...] = (),
) -> ConditionallyCheckedPlan:
    """Mint a runtime-eligible conditional state after certificate replay.

    This deliberately private bridge is the only construction route that can
    carry static-replay provenance into ``run_plain_explain_and_verify``.
    The certificate layer must authenticate its replay result *and bind the
    replayed draft identity* before calling it; a successful replay may not
    be reused with another internally well-formed SQL draft.  The runtime
    independently checks the resulting capability and still performs plain
    EXPLAIN, dynamic H2 validation, and transaction binding.
    """

    _require_digest(replay_draft_identity_digest, "replay_draft_identity_digest")
    if replay_draft_identity_digest != draft.identity_digest:
        raise ExecutionIdentityError(
            "verified replay draft identity does not match the supplied ExecutableDraft"
        )
    obligations = _normalize_dynamic_obligations(pending_dynamic_obligations)
    capability = _StaticReplayCapability(
        draft_identity_digest=draft.identity_digest,
        static_certificate_digest=static_certificate_digest,
        conditional_sigma_digest=conditional_sigma_digest,
        pending_dynamic_obligations_digest=_dynamic_obligations_digest(obligations),
        token=_TYPE_STATE_TOKEN,
    )
    plan = ConditionallyCheckedPlan(
        draft=draft,
        static_certificate_digest=static_certificate_digest,
        conditional_sigma_digest=conditional_sigma_digest,
        pending_dynamic_obligations=obligations,
        _static_replay_capability=capability,
        _construction_token=_TYPE_STATE_TOKEN,
    )
    _register_verified_conditional_plan(plan)
    return plan


def _register_verified_conditional_plan(plan: ConditionallyCheckedPlan) -> None:
    key = id(plan)

    def _drop(reference: weakref.ReferenceType[ConditionallyCheckedPlan]) -> None:
        if _VERIFIED_CONDITIONAL_PLANS.get(key) is reference:
            _VERIFIED_CONDITIONAL_PLANS.pop(key, None)

    _VERIFIED_CONDITIONAL_PLANS[key] = weakref.ref(plan, _drop)


def _is_registered_verified_conditional_plan(plan: ConditionallyCheckedPlan) -> bool:
    reference = _VERIFIED_CONDITIONAL_PLANS.get(id(plan))
    return reference is not None and reference() is plan


def _has_verified_static_replay(plan: ConditionallyCheckedPlan) -> bool:
    """Return whether a conditional plan has an internally bound replay seal."""

    capability = plan._static_replay_capability
    return (
        isinstance(capability, _StaticReplayCapability)
        and _is_registered_verified_conditional_plan(plan)
        and capability.draft_identity_digest == plan.draft.identity_digest
        and capability.static_certificate_digest == plan.static_certificate_digest
        and capability.conditional_sigma_digest == plan.conditional_sigma_digest
        and capability.pending_dynamic_obligations_digest
        == _dynamic_obligations_digest(plan.pending_dynamic_obligations)
    )


@dataclass(frozen=True)
class PlainExplainEvidence:
    """A pre-execution physical-plan observation.

    ``analyze`` and ``executed_body`` are explicit so a caller cannot relabel
    an ``EXPLAIN ANALYZE`` result as a planning-only fact.
    """

    plan_digest: str
    static_anchor_digest: str
    environment_digest: str
    analyze: bool = False
    executed_body: bool = False

    def __post_init__(self) -> None:
        for label, value in (
            ("plain EXPLAIN plan_digest", self.plan_digest),
            ("plain EXPLAIN static_anchor_digest", self.static_anchor_digest),
            ("plain EXPLAIN environment_digest", self.environment_digest),
        ):
            _require_digest(value, label)
        if self.analyze or self.executed_body:
            raise ExecutionIdentityError(
                "Prospective evidence must come from plain EXPLAIN without execution"
            )


@dataclass(frozen=True)
class ProspectivelyRankablePlan:
    """A checked plan with planning-only physical evidence; still not executable."""

    conditional_plan: ConditionallyCheckedPlan
    explain_plan_digest: str
    prospective_total_cost: float
    static_anchor_digest: str
    planning_environment_digest: str
    _construction_token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError(
                "ProspectivelyRankablePlan requires a successful plain-EXPLAIN transition"
            )
        if not isinstance(self.conditional_plan, ConditionallyCheckedPlan):
            raise ExecutionIdentityError("prospective plan requires a conditional plan")
        _require_digest(self.explain_plan_digest, "explain_plan_digest")
        _require_digest(self.static_anchor_digest, "static_anchor_digest")
        _require_digest(self.planning_environment_digest, "planning_environment_digest")
        if not math.isfinite(float(self.prospective_total_cost)) or self.prospective_total_cost < 0:
            raise ExecutionIdentityError("prospective_total_cost must be a finite nonnegative value")

    @property
    def identity_digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "conditional_plan": self.conditional_plan.identity_digest,
                    "explain_plan_digest": self.explain_plan_digest,
                    "prospective_total_cost": self.prospective_total_cost,
                    "static_anchor_digest": self.static_anchor_digest,
                    "planning_environment_digest": self.planning_environment_digest,
                }
            )
        )


def make_prospectively_rankable_plan(
    *,
    conditional_plan: ConditionallyCheckedPlan,
    plain_explain: PlainExplainEvidence,
    prospective_total_cost: float,
) -> ProspectivelyRankablePlan:
    """Upgrade only from verified non-executing physical-plan evidence."""

    return ProspectivelyRankablePlan(
        conditional_plan=conditional_plan,
        explain_plan_digest=plain_explain.plan_digest,
        prospective_total_cost=float(prospective_total_cost),
        static_anchor_digest=plain_explain.static_anchor_digest,
        planning_environment_digest=plain_explain.environment_digest,
        _construction_token=_TYPE_STATE_TOKEN,
    )


@dataclass(frozen=True)
class DynamicEvidence:
    """One validator-produced, trial-local dynamic H2 fact."""

    obligation_id: str
    fact_id: str
    transaction_snapshot_id: str
    evidence_digest: str
    kind: str
    subject_digest: str
    validator_version: str
    recipe_digest: str
    verdict: str = "pass"

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (
                self.obligation_id,
                self.fact_id,
                self.transaction_snapshot_id,
                self.kind,
                self.subject_digest,
                self.validator_version,
                self.recipe_digest,
            )
        ):
            raise ExecutionIdentityError(
                "dynamic evidence requires obligation, fact, recipe, and snapshot identity"
            )
        _require_digest(self.evidence_digest, "dynamic evidence_digest")
        _require_digest(self.recipe_digest, "dynamic evidence recipe_digest")
        if self.verdict != "pass":
            raise ExecutionIdentityError("only passing dynamic evidence can authorize execution")

    def matches_obligation(self, obligation: DynamicObligation) -> bool:
        return (
            self.obligation_id == obligation.obligation_id
            and self.kind == obligation.kind
            and self.subject_digest == obligation.subject_digest
            and self.validator_version == obligation.validator_version
            and self.recipe_digest == obligation.recipe_digest
        )


def _dynamic_evidence_digest(evidence: tuple[DynamicEvidence, ...]) -> str:
    return _digest(
        _canonical_json(
            [
                {
                    "obligation_id": item.obligation_id,
                    "fact_id": item.fact_id,
                    "transaction_snapshot_id": item.transaction_snapshot_id,
                    "evidence_digest": item.evidence_digest,
                    "kind": item.kind,
                    "subject_digest": item.subject_digest,
                    "validator_version": item.validator_version,
                    "recipe_digest": item.recipe_digest,
                    "verdict": item.verdict,
                }
                for item in sorted(evidence, key=lambda item: item.obligation_id)
            ]
        )
    )


@dataclass(frozen=True)
class AuthorizedExecution:
    """The only execution-capable object, scoped to one transaction snapshot."""

    prospective_plan: ProspectivelyRankablePlan
    completed_certificate_digest: str
    dynamic_evidence_digest: str
    transaction_snapshot_id: str
    dynamic_evidence: tuple[DynamicEvidence, ...]
    _transaction_capability: _TransactionAuthorizationCapability | None = field(
        repr=False,
        compare=False,
        default=None,
    )
    _construction_token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError(
                "AuthorizedExecution requires current-snapshot dynamic authorization"
            )
        if not isinstance(self.prospective_plan, ProspectivelyRankablePlan):
            raise ExecutionIdentityError("authorized execution requires a prospective plan")
        _require_digest(self.completed_certificate_digest, "completed_certificate_digest")
        _require_digest(self.dynamic_evidence_digest, "dynamic_evidence_digest")
        if not self.transaction_snapshot_id:
            raise ExecutionIdentityError("authorized execution requires a transaction snapshot ID")
        evidence = tuple(self.dynamic_evidence)
        if any(not isinstance(item, DynamicEvidence) for item in evidence):
            raise ExecutionIdentityError("dynamic evidence must contain DynamicEvidence values")
        if any(item.transaction_snapshot_id != self.transaction_snapshot_id for item in evidence):
            raise ExecutionIdentityError("dynamic evidence snapshot does not match authorization snapshot")
        if _dynamic_evidence_digest(evidence) != self.dynamic_evidence_digest:
            raise ExecutionIdentityError("dynamic evidence digest does not match authorization evidence")
        expected_by_id = {
            item.obligation_id: item
            for item in self.prospective_plan.conditional_plan.pending_dynamic_obligations
        }
        actual = {item.obligation_id for item in evidence}
        if set(expected_by_id) != actual:
            raise ExecutionIdentityError("dynamic evidence does not exactly discharge pending obligations")
        if len(actual) != len(evidence):
            raise ExecutionIdentityError("dynamic evidence has duplicate obligation IDs")
        if any(
            not item.matches_obligation(expected_by_id[item.obligation_id])
            for item in evidence
        ):
            raise ExecutionIdentityError(
                "dynamic evidence does not match the pending validation recipe"
            )
        if self._transaction_capability is not None and not isinstance(
            self._transaction_capability, _TransactionAuthorizationCapability
        ):
            raise ExecutionIdentityError("authorized execution has an invalid transaction capability")

    @property
    def draft(self) -> ExecutableDraft:
        return self.prospective_plan.conditional_plan.draft

    @property
    def identity_digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "prospective_plan": self.prospective_plan.identity_digest,
                    "completed_certificate_digest": self.completed_certificate_digest,
                    "dynamic_evidence_digest": self.dynamic_evidence_digest,
                    "transaction_snapshot_id": self.transaction_snapshot_id,
                }
            )
        )


def authorize_execution(
    *,
    prospective_plan: ProspectivelyRankablePlan,
    completed_certificate_digest: str,
    transaction_snapshot_id: str,
    dynamic_evidence: tuple[DynamicEvidence, ...] = (),
) -> AuthorizedExecution:
    """Build a detached authorization record for inspection only.

    This public compatibility constructor intentionally does *not* mint the
    transaction-owned capability required by :func:`run_authorized`.  Real
    adapters use ``_authorize_execution_for_transaction`` after dynamic H2
    has completed in their current transaction.
    """

    return _build_authorized_execution(
        prospective_plan=prospective_plan,
        completed_certificate_digest=completed_certificate_digest,
        transaction_snapshot_id=transaction_snapshot_id,
        dynamic_evidence=dynamic_evidence,
        transaction_capability=None,
    )


def _build_authorized_execution(
    *,
    prospective_plan: ProspectivelyRankablePlan,
    completed_certificate_digest: str,
    transaction_snapshot_id: str,
    dynamic_evidence: tuple[DynamicEvidence, ...],
    transaction_capability: _TransactionAuthorizationCapability | None,
) -> AuthorizedExecution:
    evidence = tuple(dynamic_evidence)
    return AuthorizedExecution(
        prospective_plan=prospective_plan,
        completed_certificate_digest=completed_certificate_digest,
        dynamic_evidence_digest=_dynamic_evidence_digest(evidence),
        transaction_snapshot_id=transaction_snapshot_id,
        dynamic_evidence=evidence,
        _transaction_capability=transaction_capability,
        _construction_token=_TYPE_STATE_TOKEN,
    )


def _authorize_execution_for_transaction(
    *,
    prospective_plan: ProspectivelyRankablePlan,
    completed_certificate_digest: str,
    transaction_snapshot_id: str,
    dynamic_evidence: tuple[DynamicEvidence, ...],
    transaction_owner: object,
) -> AuthorizedExecution:
    """Mint the only authorization form accepted at a runner boundary.

    Kept private so a concrete transaction adapter, rather than planning code
    or a report deserializer, owns the last transition before execution.
    """

    if transaction_owner is None:
        raise ExecutionIdentityError("transaction owner is required for executable authorization")
    return _build_authorized_execution(
        prospective_plan=prospective_plan,
        completed_certificate_digest=completed_certificate_digest,
        transaction_snapshot_id=transaction_snapshot_id,
        dynamic_evidence=dynamic_evidence,
        transaction_capability=_TransactionAuthorizationCapability(
            transaction_owner,
            _TYPE_STATE_TOKEN,
        ),
    )


def _authorization_belongs_to(execution: AuthorizedExecution, owner: object) -> bool:
    """Return whether execution carries the exact live adapter capability."""

    capability = execution._transaction_capability
    return isinstance(capability, _TransactionAuthorizationCapability) and capability.owner is owner


@dataclass(frozen=True)
class ExecutionReceipt:
    """Identity receipt emitted after an already-authorized execution."""

    plan_id: str
    exact_sql_digest: str
    parameter_digest: str
    session_digest: str
    transaction_snapshot_id: str
    wrapper_kind: str
    authorization_digest: str
    runner_body_binding_digest: str
    result_evidence_digest: str
    _construction_token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._construction_token is not _TYPE_STATE_TOKEN:
            raise ExecutionIdentityError("ExecutionReceipt must be created from AuthorizedExecution")
        if not self.plan_id or not self.transaction_snapshot_id or not self.wrapper_kind:
            raise ExecutionIdentityError("receipt requires plan, snapshot, and wrapper identity")
        for label, value in (
            ("receipt exact_sql_digest", self.exact_sql_digest),
            ("receipt parameter_digest", self.parameter_digest),
            ("receipt session_digest", self.session_digest),
            ("receipt authorization_digest", self.authorization_digest),
            ("receipt runner_body_binding_digest", self.runner_body_binding_digest),
            ("receipt result_evidence_digest", self.result_evidence_digest),
        ):
            _require_digest(value, label)


def make_execution_receipt(
    *,
    authorized: AuthorizedExecution,
    execution_snapshot_id: str,
    wrapper_kind: str,
    runner_body_binding_digest: str,
    result_evidence_digest: str,
) -> ExecutionReceipt:
    """Create a receipt only when validation and execution used one snapshot."""

    if not isinstance(authorized, AuthorizedExecution):
        raise ExecutionIdentityError("runner requires AuthorizedExecution")
    if not isinstance(authorized._transaction_capability, _TransactionAuthorizationCapability):
        raise ExecutionIdentityError(
            "execution receipt requires transaction-owned AuthorizedExecution"
        )
    if execution_snapshot_id != authorized.transaction_snapshot_id:
        raise ExecutionIdentityError("execution snapshot differs from authorization snapshot")
    if not wrapper_kind:
        raise ExecutionIdentityError("receipt wrapper_kind is required")
    _require_digest(result_evidence_digest, "result_evidence_digest")
    _require_digest(runner_body_binding_digest, "runner_body_binding_digest")
    draft = authorized.draft
    return ExecutionReceipt(
        plan_id=draft.plan_id,
        exact_sql_digest=draft.exact_sql_digest,
        parameter_digest=draft.parameter_digest,
        session_digest=draft.session_contract.digest,
        transaction_snapshot_id=execution_snapshot_id,
        wrapper_kind=wrapper_kind,
        authorization_digest=authorized.identity_digest,
        runner_body_binding_digest=runner_body_binding_digest,
        result_evidence_digest=result_evidence_digest,
        _construction_token=_TYPE_STATE_TOKEN,
    )


class AuthorizedExecutionRunner(Protocol):
    """Narrow runner API: no raw SQL, params, or session are accepted."""

    def _accepts_transaction_authorization(self, execution: AuthorizedExecution) -> bool:
        """Confirm that this live adapter minted ``execution`` for itself."""
        ...

    def execute_authorized(
        self,
        execution: AuthorizedExecution,
        body_binding: RunnerBodyBinding,
    ) -> Mapping[str, Any]:
        ...


def run_authorized(
    execution: AuthorizedExecution,
    runner: AuthorizedExecutionRunner,
    *,
    wrapper_kind: str = "direct",
) -> ExecutionReceipt:
    """Execute through the type-safe runner interface and return a receipt.

    A concrete PostgreSQL adapter must expose only ``execute_authorized``.  It
    receives the bound object, not a free SQL string, which makes accidental
    substitution impossible at this boundary.
    """

    if not isinstance(execution, AuthorizedExecution):
        raise ExecutionIdentityError("runner requires AuthorizedExecution")
    execution.draft.assert_identity_intact()
    if not isinstance(execution._transaction_capability, _TransactionAuthorizationCapability):
        raise ExecutionIdentityError(
            "runner requires transaction-owned AuthorizedExecution"
        )
    if not _authorization_belongs_to(execution, runner):
        raise ExecutionIdentityError(
            "AuthorizedExecution is not owned by this current transaction adapter"
        )
    accepts = getattr(runner, "_accepts_transaction_authorization", None)
    if not callable(accepts) or not bool(accepts(execution)):
        raise ExecutionIdentityError(
            "AuthorizedExecution is not minted by this current transaction adapter"
        )
    body_binding = bind_runner_body(
        execution.draft,
        sql_text=execution.draft.sql_text,
        typed_params=execution.draft.typed_params,
        session_contract=execution.draft.session_contract,
    )
    payload = runner.execute_authorized(execution, body_binding)
    if not isinstance(payload, Mapping):
        raise ExecutionIdentityError("authorized runner returned an invalid receipt payload")
    snapshot_id = str(payload.get("transaction_snapshot_id") or "")
    result_evidence_digest = str(payload.get("result_evidence_digest") or "")
    payload_binding_digest = str(payload.get("runner_body_binding_digest") or "")
    payload_wrapper_kind = str(payload.get("wrapper_kind") or wrapper_kind)
    if payload_wrapper_kind != wrapper_kind:
        raise ExecutionIdentityError("authorized runner changed the requested execution wrapper")
    if payload_binding_digest != body_binding.identity_digest:
        raise ExecutionIdentityError("authorized runner did not execute the bound draft body")
    return make_execution_receipt(
        authorized=execution,
        execution_snapshot_id=snapshot_id,
        wrapper_kind=payload_wrapper_kind,
        runner_body_binding_digest=payload_binding_digest,
        result_evidence_digest=result_evidence_digest,
    )
