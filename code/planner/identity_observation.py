"""Observe a finite, explicitly trusted object DAG without serializing it.

This module does not admit a plan or create an identity seal. A caller may use
an unchanged observation only after its normal full check has succeeded. The
caller must separately pin the ambient module/registry state used by trusted
methods: function globals are deliberately not traversed here. Unknown data,
custom mapping callbacks, cycles, or unsupported descriptors disable capture.

Children are retained to prevent object-id reuse. Do not include an owning
result in ``roots``; pass its id in ``forbidden_ids`` to reject back references.
"""

from __future__ import annotations

import builtins
from dataclasses import (
    Field, FrozenInstanceError, MISSING, _FIELD, _FIELD_CLASSVAR,
    _FIELD_INITVAR, _HAS_DEFAULT_FACTORY, dataclass, fields, is_dataclass,
)
import functools
import gc
from types import (
    BuiltinFunctionType, CellType, FunctionType, GetSetDescriptorType,
    MappingProxyType, MemberDescriptorType, ModuleType,
)
from typing import Any, Iterable

from ._identity_native_loader import backend_info, load_native

_NATIVE = load_native()


_ATOM_TYPES = frozenset((type(None), str, bytes, int, bool, float, complex,
                        type(Ellipsis), type(NotImplemented), object))
_IMMUTABLE_TYPE_OBJECTS = (type(None), str, bytes, int, bool, float, complex,
                           list, tuple, dict, set, frozenset, object, type, map, zip)
_TUPLE_GETTER_TYPE = type(__import__("collections").namedtuple("_Getter", "value").value)
_MISSING = object()


class _Unsupported(Exception):
    pass


def _same_edges(actual: tuple[object, ...], expected: tuple[object, ...]) -> bool:
    # Exact tuples retain their element identities. Mutable descendants are
    # separate DAG nodes and are still checked on every observation.
    if actual is expected:
        return True
    if _NATIVE is not None:
        result = _NATIVE.same_edges(actual, expected)
        if result is not NotImplemented:
            return result
    return len(actual) == len(expected) and all(
        left is right for left, right in zip(actual, expected)
    )


def _raw_dict(value: object) -> dict | None:
    for base in type.__getattribute__(type(value), "__mro__"):
        namespace = type.__getattribute__(base, "__dict__")
        descriptor = namespace.get("__dict__", _MISSING)
        if descriptor is _MISSING:
            continue
        if type(descriptor) is not GetSetDescriptorType:
            raise _Unsupported("custom instance dictionary descriptor")
        result = descriptor.__get__(value, type(value))
        if type(result) is not dict:
            raise _Unsupported("instance dictionary is not an exact dict")
        return result
    return None


def _mapping_edges(value: dict | MappingProxyType) -> tuple[object, ...]:
    return tuple(item for pair in value.items() for item in pair)


def _mapping_matches(value: dict | MappingProxyType, expected: tuple[object, ...]) -> bool:
    if _NATIVE is not None:
        result = _NATIVE.mapping_matches(value, expected)
        if result is not NotImplemented:
            return result
    if 2 * len(value) != len(expected):
        return False
    index = 0
    for key, item in value.items():
        if key is not expected[index] or item is not expected[index + 1]:
            return False
        index += 2
    return True


@dataclass(frozen=True)
class _Node:
    value: object
    kind: str
    expected: tuple[object, ...]
    slots: tuple[MemberDescriptorType, ...] = ()
    defaults: tuple[tuple[str, object], ...] = ()
    dictionary: dict | None = None
    member_ids: frozenset[int] = frozenset()

    def unchanged(self) -> bool:
        value = self.value
        kind = self.kind
        if kind == "list":
            return type(value) is list and len(value) == len(self.expected) and all(
                actual is expected for actual, expected in zip(value, self.expected)
            )
        if kind == "tuple":
            return type(value) is tuple and _same_edges(value, self.expected)
        if kind == "dict":
            return type(value) is dict and _mapping_matches(value, self.expected)
        if kind == "proxy":
            referents = gc.get_referents(value)
            return (
                type(value) is MappingProxyType and len(referents) == 1
                and referents[0] is self.dictionary
                and _mapping_matches(value, self.expected)
            )
        if kind in {"set", "frozenset"}:
            expected_type = set if kind == "set" else frozenset
            if type(value) is not expected_type or len(value) != len(self.expected):
                return False
            return all(id(item) in self.member_ids for item in value)
        if kind == "function":
            return type(value) is FunctionType and _same_edges(
                (value.__code__, value.__defaults__, value.__kwdefaults__,
                 value.__closure__, value.__dict__, value.__annotations__),
                self.expected,
            )
        if kind == "cell":
            try:
                content = value.cell_contents
            except ValueError:
                content = _MISSING
            return type(value) is CellType and content is self.expected[0]
        if type(value) is not self.expected[0]:
            return False
        if kind == "namedtuple":
            if not _same_edges(tuple(tuple.__iter__(value)), self.expected[1:]):
                return False
        else:
            current = tuple(_slot_value(descriptor, value) for descriptor in self.slots)
            if not _same_edges(current, self.expected[1:]):
                return False
            for name, default in self.defaults:
                namespace_value = _class_attribute(type(value), name)
                if namespace_value is not default:
                    return False
        return _raw_dict(value) is self.dictionary


def _slot_value(descriptor: MemberDescriptorType, value: object) -> object:
    try:
        return descriptor.__get__(value, type(value))
    except AttributeError:
        return _MISSING


def _class_attribute(cls: type, name: str) -> object:
    for base in type.__getattribute__(cls, "__mro__"):
        namespace = type.__getattribute__(base, "__dict__")
        if name in namespace:
            return namespace[name]
    return _MISSING


def _is_descriptor(value: object) -> bool:
    return any(
        "__get__" in type.__getattribute__(base, "__dict__")
        for base in type.__getattribute__(type(value), "__mro__")
    )


def _field_schema(cls: type) -> tuple[object, ...]:
    raw = _class_attribute(cls, "__dataclass_fields__")
    if raw is _MISSING:
        return ()
    if type(raw) is not dict:
        raise _Unsupported("dataclass field catalog is not an exact dict")
    params = _class_attribute(cls, "__dataclass_params__")
    if type(params) is not type(_Node.__dataclass_params__):
        raise _Unsupported("custom dataclass parameters")
    parameter_values = tuple(
        type.__getattribute__(type(params), "__dict__")[name].__get__(params, type(params))
        for name in type(params).__slots__
    )
    if any(type(value) is not bool for value in parameter_values):
        raise _Unsupported("non-boolean dataclass parameters")
    result: list[object] = [raw, params, *parameter_values]
    # These are the same trusted stdlib descriptors used below for every
    # field; look them up once per schema check, rather than per field.
    field_namespace = type.__getattribute__(Field, "__dict__")
    field_descriptors = tuple(field_namespace[name] for name in Field.__slots__)
    for key, item in raw.items():
        if type(item) is not Field:
            raise _Unsupported("custom dataclass field catalog value")
        result.extend((key, item))
        result.extend(
            descriptor.__get__(item, Field) for descriptor in field_descriptors
        )
    result.extend(field.name for field in fields(cls))
    return tuple(result)


@dataclass(frozen=True)
class _ClassState:
    cls: type
    lineage: tuple[type, ...]
    namespaces: tuple[tuple[type, tuple[object, ...]], ...]
    schema: tuple[object, ...]
    descriptors: tuple[tuple[object, tuple[object, ...]], ...]

    def unchanged(self) -> bool:
        if type(self.cls) is not type:
            return False
        if not _same_edges(type.__getattribute__(self.cls, "__mro__"), self.lineage):
            return False
        for base, expected in self.namespaces:
            result = (_NATIVE.type_namespace_matches(base, expected)
                      if _NATIVE is not None else NotImplemented)
            if result is NotImplemented:
                result = _mapping_matches(type.__getattribute__(base, "__dict__"), expected)
            if not result:
                return False
        if not _same_edges(_field_schema(self.cls), self.schema):
            return False
        for descriptor, expected in self.descriptors:
            if type(descriptor) is property:
                actual = (descriptor.fget, descriptor.fset, descriptor.fdel, descriptor.__doc__)
            else:
                actual = _mapping_edges(object.__getattribute__(descriptor, "__dict__"))
            if not _same_edges(actual, expected):
                return False
        return True


class Observation:
    """Captured child DAG; ``False`` means use the caller's original full check."""

    __slots__ = ("_nodes", "_classes", "node_count", "edge_count", "check_count",
                 "last_node_checks", "total_node_checks", "_native_nodes", "_native_owner")

    def __init__(self, nodes: tuple[_Node, ...], classes: tuple[_ClassState, ...]) -> None:
        self._nodes = nodes
        self._classes = classes
        self._native_owner = _NATIVE
        self._native_nodes = (None if _NATIVE is None else tuple(
            ({"list": 1, "tuple": 2, "dict": 3}.get(node.kind, 0),
             node.value, node.expected, node) for node in nodes))
        self.node_count = len(nodes)
        self.edge_count = sum(len(node.expected) for node in nodes)
        self.check_count = 0
        self.last_node_checks = 0
        self.total_node_checks = 0

    def unchanged(self) -> bool:
        self.check_count += 1
        self.last_node_checks = 0
        checked = 0
        try:
            # Check behavior/schema before reading any recorded slot descriptor.
            for state in self._classes:
                if not state.unchanged():
                    return False
            if (_NATIVE is not None and _NATIVE is self._native_owner
                    and self._native_nodes is not None):
                result, checked, error = _NATIVE.check_nodes(self._native_nodes)
                if error is not None:
                    raise error
                return result
            for node in self._nodes:
                checked += 1
                if not node.unchanged():
                    return False
            return True
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError, _Unsupported):
            return False
        finally:
            self.last_node_checks = checked
            self.total_node_checks += checked


def capture_observation(
    roots: tuple[object, ...], *, trusted_types: Iterable[type] = (),
    forbidden_ids: Iterable[int] = (),
) -> Observation | None:
    """Capture exact builtin data and whitelisted immutable typed instances.

    Trusted classes must be normal-metaclass frozen dataclasses, NamedTuples,
    or pure-slot classes. Their namespace and method state are observed, but
    ambient globals accessed by those methods remain the caller's obligation.
    ``None`` is a normal fallback, including unsupported objects and cycles.
    No user ``to_dict``, iteration, equality, hashing, or custom getter is called.
    """

    if type(roots) is not tuple:
        return None
    requested_types = tuple(trusted_types)
    if any(type(cls) is not type for cls in requested_types):
        return None
    trusted = frozenset(requested_types)
    forbidden = frozenset(forbidden_ids)
    states: dict[int, int] = {}
    nodes: list[_Node] = []
    classes: dict[type, _ClassState] = {}
    behavior_functions: set[int] = set()
    behavior_cells: set[int] = set()

    def class_state(cls: type) -> tuple[object, ...]:
        if cls in classes:
            return ()
        if type(cls) is not type:
            raise _Unsupported("custom metaclass")
        mro = type.__getattribute__(cls, "__mro__")
        namespaces = []
        descriptors = []
        dependencies: list[object] = []
        factory_classes: list[type] = []
        for base in mro:
            if base in (object, tuple):
                continue
            if type(base) is not type:
                raise _Unsupported("custom base metaclass")
            namespace = type.__getattribute__(base, "__dict__")
            getter = namespace.get("__getattribute__")
            if getter is not None and getter is not object.__getattribute__:
                raise _Unsupported("custom attribute reader")
            namespaces.append((base, _mapping_edges(namespace)))
            for name, item in namespace.items():
                if id(item) in forbidden:
                    raise _Unsupported("class namespace references owning root")
                functions: tuple[object, ...] = ()
                handled_behavior = False
                if type(item) is FunctionType:
                    functions = (item,)
                    handled_behavior = True
                elif type(item) in (staticmethod, classmethod):
                    functions = (item.__func__,)
                    descriptors.append((item, _mapping_edges(item.__dict__)))
                    handled_behavior = True
                elif type(item) is property:
                    functions = tuple(f for f in (item.fget, item.fset, item.fdel) if f is not None)
                    descriptors.append((item, (item.fget, item.fset, item.fdel, item.__doc__)))
                    handled_behavior = True
                elif type(item) is functools.cached_property:
                    functions = (item.func,)
                    descriptors.append((item, _mapping_edges(item.__dict__)))
                    handled_behavior = True
                elif type(item) in (MemberDescriptorType, GetSetDescriptorType, _TUPLE_GETTER_TYPE):
                    handled_behavior = True
                elif _is_descriptor(item) and type(item) not in (
                    MemberDescriptorType, GetSetDescriptorType, _TUPLE_GETTER_TYPE,
                ):
                    raise _Unsupported("unknown class descriptor")
                elif callable(item) and type(item) is not type:
                    raise _Unsupported("unknown callable class behavior")
                for function in functions:
                    if type(function) is not FunctionType:
                        raise _Unsupported("unknown behavior wrapper")
                    behavior_functions.add(id(function))
                    dependencies.append(function)
                # Every remaining value is data, including unknown non-callable
                # objects. Do not silently leave mutable class state outside
                # the closure just because it is not a builtin container.
                if not handled_behavior and name not in {"__dataclass_fields__", "__dataclass_params__"}:
                    dependencies.append(item)
        catalog = _class_attribute(cls, "__dataclass_fields__")
        if catalog is not _MISSING:
            if type(catalog) is not dict or any(type(item) is not Field for item in catalog.values()):
                raise _Unsupported("custom dataclass field catalog")
            for item in catalog.values():
                dependencies.extend((item.type, item.metadata, item.default,
                                     item.repr, item.hash, item.init, item.compare,
                                     item._field_type))
                factory = item.default_factory
                if factory is MISSING:
                    continue
                if type(factory) is FunctionType:
                    behavior_functions.add(id(factory))
                    dependencies.append(factory)
                elif not any(factory is known for known in _IMMUTABLE_TYPE_OBJECTS):
                    # Arbitrary factory objects/classes have behavior outside
                    # the raw data closure; a caller can use the full seal.
                    if type(factory) is not type or factory not in trusted:
                        raise _Unsupported("unknown dataclass default factory")
                    factory_classes.append(factory)
        classes[cls] = _ClassState(cls, mro, tuple(namespaces), _field_schema(cls), tuple(descriptors))
        for factory_class in factory_classes:
            dependencies.extend(class_state(factory_class))
        return tuple(dependencies)

    def describe(value: object) -> tuple[_Node | None, tuple[object, ...]]:
        cls = type(value)
        if type(cls) is not type:
            raise _Unsupported("custom value metaclass")
        if cls in _ATOM_TYPES:
            return None, ()
        if cls is type and any(value is item for item in _IMMUTABLE_TYPE_OBJECTS):
            return None, ()
        if any(value is token for token in (MISSING, _HAS_DEFAULT_FACTORY, _FIELD, _FIELD_CLASSVAR, _FIELD_INITVAR)):
            dictionary = _raw_dict(value)
            dependencies = class_state(cls)
            if dictionary is not None:
                dependencies += (dictionary,)
            return _Node(value, "typed", (cls,), dictionary=dictionary), dependencies
        if cls in (list, tuple):
            edges = tuple(value)
            return _Node(value, "list" if cls is list else "tuple", edges), edges
        if cls is dict:
            edges = _mapping_edges(value)
            return _Node(value, "dict", edges), edges
        if cls is MappingProxyType:
            referents = gc.get_referents(value)
            if len(referents) != 1 or type(referents[0]) is not dict:
                raise _Unsupported("mappingproxy with callback-backed mapping")
            edges = _mapping_edges(value)
            return _Node(value, "proxy", edges, dictionary=referents[0]), edges
        if cls in (set, frozenset):
            edges = tuple(value)
            return _Node(value, "set" if cls is set else "frozenset", edges, member_ids=frozenset(map(id, edges))), edges
        if cls is FunctionType and id(value) in behavior_functions:
            edges = (value.__code__, value.__defaults__, value.__kwdefaults__,
                     value.__closure__, value.__dict__, value.__annotations__)
            if value.__closure__:
                for cell in value.__closure__:
                    behavior_cells.add(id(cell))
                    try:
                        content = cell.cell_contents
                    except ValueError:
                        continue
                    if type(content) is FunctionType:
                        behavior_functions.add(id(content))
            # Code objects are immutable behavior identities, not data roots.
            return _Node(value, "function", edges), edges[1:]
        if cls is CellType and id(value) in behavior_cells:
            try:
                content = value.cell_contents
            except ValueError:
                content = _MISSING
            node = _Node(value, "cell", (content,))
            if id(content) in forbidden:
                raise _Unsupported("behavior cell references owning root")
            if content is MISSING or content is _HAS_DEFAULT_FACTORY or content is FrozenInstanceError:
                return node, ()
            if content is builtins:
                return node, ()
            if type(content) is BuiltinFunctionType:
                owner = content.__self__
                if owner is None or owner is builtins or any(owner is item for item in _IMMUTABLE_TYPE_OBJECTS):
                    return node, ()
            if type(content) is type and any(
                any(content is base for base in state.lineage) for state in classes.values()
            ):
                return node, ()
            if type(content) is type and content in trusted:
                return node, class_state(content)
            return node, (content,)
        if cls not in trusted:
            raise _Unsupported("untrusted value type")
        dependencies = class_state(cls)
        dictionary = _raw_dict(value)
        if issubclass(cls, tuple) and type(getattr(cls, "_fields", None)) is tuple:
            edges = tuple(tuple.__iter__(value))
            return _Node(value, "namedtuple", (cls,) + edges, dictionary=dictionary), edges + dependencies + (() if dictionary is None else (dictionary,))
        dataclass_instance = is_dataclass(cls)
        if dataclass_instance and not cls.__dataclass_params__.frozen:
            raise _Unsupported("mutable dataclass")
        slots = tuple(
            descriptor
            for base in type.__getattribute__(cls, "__mro__")
            for descriptor in type.__getattribute__(base, "__dict__").values()
            if type(descriptor) is MemberDescriptorType
        )
        if not dataclass_instance and (not slots or dictionary is not None):
            raise _Unsupported("trusted non-dataclass must be pure slots")
        defaults = []
        if dataclass_instance:
            for field in fields(cls):
                attribute = _class_attribute(cls, field.name)
                if type(attribute) is not MemberDescriptorType and _is_descriptor(attribute):
                    raise _Unsupported("custom dataclass field descriptor")
                if dictionary is not None and field.name in dictionary:
                    continue
                if type(attribute) is MemberDescriptorType:
                    continue
                defaults.append((field.name, attribute))
        slot_values = tuple(_slot_value(descriptor, value) for descriptor in slots)
        node = _Node(value, "typed", (cls,) + slot_values, slots, tuple(defaults), dictionary)
        edges = slot_values + tuple(item for _, item in defaults) + dependencies
        if dictionary is not None:
            edges += (dictionary,)
        return node, edges

    def visit(value: object) -> None:
        identity = id(value)
        if identity in forbidden:
            raise _Unsupported("forbidden owning root reference")
        state = states.get(identity)
        if state == 1:
            raise _Unsupported("cycle")
        if state == 2:
            return
        states[identity] = 1
        node, edges = describe(value)
        if node is not None:
            nodes.append(node)
        for child in edges:
            visit(child)
        states[identity] = 2

    try:
        for root in roots:
            visit(root)
        observation = Observation(tuple(nodes), tuple(classes.values()))
        return observation if observation.unchanged() else None
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError, RecursionError, _Unsupported):
        return None
