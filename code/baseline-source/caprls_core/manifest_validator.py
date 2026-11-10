"""Manifest validator for the CAPRLS execution skeleton."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import yaml

from .baselines import (
    ALLOWED_EVALUATION_ROLES,
    LEGACY_CONTRACT_AWARE_MODE,
    LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
    ModeSpec,
    load_mode_registry,
    normalize_mode_id,
)


PARAM_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GLOSSARY_BLOCK_RE = re.compile(
    r"Canonical CLI mode flags:\s*```text\s*(.*?)\s*```", re.DOTALL
)
API_TABLE_RE = re.compile(r"\|\s*`([^`]+)`\s*\|\s*`?([^|`]+)`?")

BUILT_IN_TEMPLATE_VARIABLES = {"alias", "rid_col"}

ARTIFACT_TEMPLATES = {
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "mav_scan_v1",
    "hybrid_intersect_v1",
}

KNOWN_TEMPLATE_CANDIDATES = {
    "barrier_filter_v1",
    "safe_predicate_injection_v1",
    "auth_view_scan_v1",
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "mav_scan_v1",
    "guard_candidate_plus_residual_v1",
    "hybrid_intersect_v1",
}

REQUIRED_SMOKE_EXPERIMENTS = {"E1", "E2", "E3", "E5", "E6", "E7", "E8", "E9"}

REQUIRED_E6A_COMPONENTS = {
    "NoDomain",
    "NoResidual",
    "NoFreshness",
    "NoContextScope",
    "NoRIDMatProps",
    "NoSafetyLevel",
    "NoBranchLineage",
    "NoPhysProps",
}

ALLOWED_ARTIFACT_ACTIONS = {"execute", "reject", "fallback", "refresh", "replan"}

REDUCED_TPCH_SCALE = "reduced_1k_customer_2k_orders_6k_lineitem"
REDUCED_JOB_SCALE = "reduced_1500_title_4000_companies_8000_cast"
ALLOWED_TPCH_SCALES = {"SF1", "SF10", "SF100", REDUCED_TPCH_SCALE}
ALLOWED_JOB_SCALES = {"selected", "full", REDUCED_JOB_SCALE}


@dataclass(frozen=True)
class ValidationIssue:
    level: str
    path: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    errors: Sequence[ValidationIssue]
    warnings: Sequence[ValidationIssue]
    manifest_hashes: Mapping[str, str]
    checked_manifests: int
    checked_policies: int
    checked_modes: int

    @property
    def ok(self) -> bool:
        return not self.errors


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def scientific_manifest_hash(manifest_path: Path) -> str:
    """Return the rename-invariant manifest identity used by legacy SQL hashes.

    Historical run schemas used the manifest digest as ``normalized_sql_hash``
    for paths without emitted SQL.  A taxonomy-only successor must not make that
    scientific value change.  The public ``manifest_hash`` still records the
    successor itself; this helper is only for that retained scientific field.
    """

    path = Path(manifest_path)
    data = load_yaml(path)
    if data.get("manifest_schema") != "caprls-experiment-manifest-v3":
        return file_sha256(path)

    lineage = data.get("lineage")
    if not isinstance(lineage, Mapping):
        raise ValueError(f"{path}: v3 manifest requires lineage mapping")
    predecessor_path = lineage.get("predecessor_path")
    predecessor_sha256 = lineage.get("predecessor_sha256")
    if not isinstance(predecessor_path, str) or not predecessor_path:
        raise ValueError(f"{path}: lineage missing predecessor_path")
    if not isinstance(predecessor_sha256, str) or not SHA256_RE.fullmatch(
        predecessor_sha256
    ):
        raise ValueError(f"{path}: lineage predecessor_sha256 is invalid")

    manifests_root = next(
        (parent for parent in path.resolve().parents if parent.name == "manifests"),
        None,
    )
    if manifests_root is None:
        raise ValueError(f"{path}: cannot locate repository manifests directory")
    repo_root = manifests_root.parent.resolve()
    predecessor = (repo_root / predecessor_path).resolve()
    try:
        predecessor.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"{path}: lineage predecessor escapes repository root") from exc
    if not predecessor.is_file():
        raise ValueError(f"{path}: lineage predecessor is missing: {predecessor_path}")
    if file_sha256(predecessor) != predecessor_sha256:
        raise ValueError(f"{path}: lineage predecessor hash does not match")
    return predecessor_sha256


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _manifest_yaml_paths(directory: Path) -> Tuple[Path, ...]:
    """Return real YAML manifests while ignoring macOS AppleDouble sidecars."""

    return tuple(
        sorted(
            path
            for path in directory.rglob("*.yaml")
            if path.is_file() and not path.name.startswith("._")
        )
    )


class ManifestValidator:
    def __init__(self, root: Path):
        self.root = root
        self.errors: List[ValidationIssue] = []
        self.warnings: List[ValidationIssue] = []
        self.manifest_hashes: Dict[str, str] = {}
        self._policy_catalog: Dict[str, Mapping[str, Any]] = {}
        self._mode_registry: Dict[str, ModeSpec] = {}
        self._glossary_modes: Set[str] = set()
        self._api_modes: Set[str] = set()
        self._synthetic_scales: Set[str] = set()

    def validate_all(self) -> ValidationReport:
        self._glossary_modes = self._load_glossary_modes()
        self._api_modes = self._load_api_modes()
        self._mode_registry = self._load_mode_registry()
        self._policy_catalog = self._load_policy_catalog()
        self._synthetic_scales = self._load_synthetic_scales()

        experiment_paths = _manifest_yaml_paths(self.root / "manifests" / "experiments")
        if not experiment_paths:
            self._error("manifests/experiments", "no experiment manifests found")

        experiment_records: List[Tuple[Path, Mapping[str, Any]]] = []
        for path in experiment_paths:
            data = self._load_yaml_checked(path)
            if isinstance(data, Mapping):
                self._validate_experiment_manifest(path, data)
                experiment_records.append((path, data))

        self._validate_required_smoke_surface(experiment_records)

        return ValidationReport(
            errors=tuple(self.errors),
            warnings=tuple(self.warnings),
            manifest_hashes=dict(self.manifest_hashes),
            checked_manifests=len(experiment_paths),
            checked_policies=len(self._policy_catalog),
            checked_modes=len(self._mode_registry),
        )

    def _load_yaml_checked(self, path: Path) -> Any:
        try:
            data = load_yaml(path)
        except yaml.YAMLError as exc:
            self._error(str(path.relative_to(self.root)), f"invalid YAML: {exc}")
            return None
        except UnicodeError as exc:
            self._error(str(path.relative_to(self.root)), f"manifest is not valid UTF-8: {exc}")
            return None
        except OSError as exc:
            self._error(str(path.relative_to(self.root)), f"cannot read file: {exc}")
            return None

        self.manifest_hashes[str(path.relative_to(self.root))] = file_sha256(path)
        return data

    def _load_glossary_modes(self) -> Set[str]:
        path = self.root / "experiment" / "17_glossary_and_contract_names.md"
        text = path.read_text(encoding="utf-8")
        match = GLOSSARY_BLOCK_RE.search(text)
        if not match:
            self._error(str(path.relative_to(self.root)), "missing canonical CLI mode block")
            return set()
        modes: Set[str] = set()
        for line in match.group(1).splitlines():
            mode = line.strip()
            if not mode:
                continue
            try:
                canonical = normalize_mode_id(mode)
            except ValueError as exc:
                self._error(str(path.relative_to(self.root)), str(exc))
                continue
            if canonical != mode:
                self._error(
                    str(path.relative_to(self.root)),
                    f"legacy CLI mode id {mode!r} is not allowed in active documentation",
                )
                continue
            modes.add(canonical)
        return modes

    def _load_api_modes(self) -> Set[str]:
        path = self.root / "experiment" / "24_baseline_mode_api.md"
        text = path.read_text(encoding="utf-8")
        start = text.find("Evaluation-role mapping:")
        end = text.find("## LocalGreedy Decision Rule")
        if start == -1 or end == -1:
            self._error(str(path.relative_to(self.root)), "missing evaluation-role table")
            return set()
        table = text[start:end]
        modes: Set[str] = set()
        for mode, _ in API_TABLE_RE.findall(table):
            if mode.strip().lower() in {
                "mode",
                "baseline_class",
                "evaluation_role",
            }:
                continue
            try:
                canonical = normalize_mode_id(mode)
            except ValueError as exc:
                self._error(str(path.relative_to(self.root)), str(exc))
                continue
            if canonical != mode:
                self._error(
                    str(path.relative_to(self.root)),
                    f"legacy API mode id {mode!r} is not allowed in active documentation",
                )
                continue
            modes.add(canonical)
        return modes

    def _load_mode_registry(self) -> Dict[str, ModeSpec]:
        try:
            registry = load_mode_registry(self.root)
        except (OSError, ValueError) as exc:
            self._error("manifests/baselines/modes.yaml", str(exc))
            return {}

        for mode, spec in registry.items():
            if mode not in self._glossary_modes:
                self._error("manifests/baselines/modes.yaml", f"{mode}: absent from glossary")
            if mode not in self._api_modes:
                self._error("manifests/baselines/modes.yaml", f"{mode}: absent from baseline API")
            if spec.evaluation_role not in ALLOWED_EVALUATION_ROLES:
                self._error(
                    "manifests/baselines/modes.yaml",
                    f"{mode}: invalid evaluation_role {spec.evaluation_role}",
                )

        return registry

    def _load_policy_catalog(self) -> Dict[str, Mapping[str, Any]]:
        paths = _manifest_yaml_paths(self.root / "manifests" / "policies")
        if not paths:
            self._error("manifests/policies", "no policy manifests found")
            return {}

        catalog: Dict[str, Mapping[str, Any]] = {}
        for path in paths:
            data = self._load_yaml_checked(path)
            if not isinstance(data, Mapping):
                self._error(str(path.relative_to(self.root)), "policy manifest must be an object")
                continue
            policies = data.get("policies")
            if not isinstance(policies, Mapping):
                self._error(str(path.relative_to(self.root)), "missing policies mapping")
                continue
            for policy_id, policy in policies.items():
                if policy_id in catalog:
                    self._error(
                        str(path.relative_to(self.root)),
                        f"duplicate policy_id {policy_id}",
                    )
                    continue
                if not isinstance(policy, Mapping):
                    self._error(
                        str(path.relative_to(self.root)),
                        f"policy {policy_id} must be an object",
                    )
                    continue
                self._validate_policy(path, str(policy_id), policy)
                catalog[str(policy_id)] = policy
        return catalog

    def _load_synthetic_scales(self) -> Set[str]:
        path = self.root / "datasets" / "manifests" / "synthetic_saas_scales.yaml"
        if not path.exists():
            self._warning(
                str(path.relative_to(self.root)),
                "synthetic_saas scale manifest is absent; synthetic dataset scale checks skipped",
            )
            return set()
        data = self._load_yaml_checked(path)
        if not isinstance(data, Mapping):
            self._error(str(path.relative_to(self.root)), "dataset manifest must be an object")
            return set()
        profiles = data.get("synthetic_saas_scale_profiles")
        if not isinstance(profiles, Mapping):
            self._error(
                str(path.relative_to(self.root)),
                "missing synthetic_saas_scale_profiles mapping",
            )
            return set()
        return {str(scale) for scale in profiles.keys()}

    def _validate_policy(self, path: Path, policy_id: str, policy: Mapping[str, Any]) -> None:
        rel_path = str(path.relative_to(self.root))
        bindings = policy.get("bindings")
        if not isinstance(bindings, Mapping):
            self._error(rel_path, f"{policy_id}: missing bindings mapping")
            bindings = {}

        applicable_relations = policy.get("applicable_relations")
        if not applicable_relations:
            self._error(rel_path, f"{policy_id}: missing applicable_relations")

        for binding in _as_list(policy.get("required_bindings")):
            if binding not in bindings:
                self._error(
                    rel_path,
                    f"{policy_id}: required binding {binding!r} absent from bindings",
                )

        for field in (
            "exact_sql_template",
            "guard_sql_template",
            "rid_exact_sql_template",
        ):
            template = policy.get(field)
            if template in (None, ""):
                continue
            params = set(PARAM_RE.findall(str(template)))
            missing = params - set(bindings.keys()) - BUILT_IN_TEMPLATE_VARIABLES
            for param in sorted(missing):
                self._error(rel_path, f"{policy_id}.{field}: :{param} has no binding")

        for field in ("exact_sql", "guard_sql", "rid_exact_sql"):
            value = policy.get(field)
            if value in (None, ""):
                continue
            sql_path = self.root / str(value)
            if not sql_path.exists():
                self._error(rel_path, f"{policy_id}.{field}: missing SQL file {value}")

    def _validate_experiment_manifest(self, path: Path, data: Mapping[str, Any]) -> None:
        rel_path = str(path.relative_to(self.root))
        manifest_id = str(data.get("manifest_id", rel_path))

        manifest_schema = data.get("manifest_schema")
        if manifest_schema is not None and manifest_schema != "caprls-experiment-manifest-v3":
            self._error(rel_path, f"{manifest_id}: invalid manifest_schema {manifest_schema!r}")
        if manifest_schema == "caprls-experiment-manifest-v3":
            self._validate_v3_lineage(
                rel_path, manifest_id, data, data.get("lineage")
            )

        for field in ("manifest_id", "experiment", "stage", "execution_tier", "timeout_s"):
            if field not in data:
                self._error(rel_path, f"{manifest_id}: missing required field {field}")

        execution_tier = data.get("execution_tier")
        if execution_tier not in {"smoke", "main", "appendix-large"}:
            self._error(rel_path, f"{manifest_id}: invalid execution_tier {execution_tier!r}")

        if "dataset" not in data and "datasets" not in data:
            self._error(rel_path, f"{manifest_id}: missing dataset or datasets")

        self._validate_dataset_declarations(rel_path, manifest_id, data)
        self._validate_manifest_modes(
            rel_path,
            manifest_id,
            _as_list(data.get("modes")),
            require_canonical=manifest_schema == "caprls-experiment-manifest-v3",
        )
        self._validate_query_paths(rel_path, manifest_id, data)
        self._validate_policy_applications(rel_path, manifest_id, data)
        self._validate_template_applicability(rel_path, manifest_id, data)
        self._validate_outputs(
            rel_path,
            manifest_id,
            data,
            require_v3_namespace=manifest_schema == "caprls-experiment-manifest-v3",
        )
        self._validate_manifest_specific_contracts(rel_path, manifest_id, data)

    def _validate_dataset_declarations(
        self, rel_path: str, manifest_id: str, data: Mapping[str, Any]
    ) -> None:
        declarations = []
        if "dataset" in data:
            declarations.extend(_as_list(data.get("dataset")))
        if "datasets" in data:
            declarations.extend(_as_list(data.get("datasets")))

        for dataset in declarations:
            if not isinstance(dataset, Mapping):
                self._error(rel_path, f"{manifest_id}: dataset declaration must be an object")
                continue
            name = dataset.get("name")
            scale = dataset.get("scale")
            if not name or scale is None:
                self._error(rel_path, f"{manifest_id}: dataset needs name and scale")
                continue
            if name == "synthetic_saas" and self._synthetic_scales:
                if str(scale) not in self._synthetic_scales and str(scale) != "variable_N":
                    known = ", ".join(sorted(self._synthetic_scales))
                    self._error(
                        rel_path,
                        f"{manifest_id}: synthetic_saas scale {scale!r} absent from "
                        f"datasets/manifests/synthetic_saas_scales.yaml ({known})",
                    )
            elif name == "synthetic_planner_stress":
                if str(scale) != "generated":
                    self._error(
                        rel_path,
                        f"{manifest_id}: synthetic_planner_stress scale must be 'generated'",
                    )
            elif name == "tpch":
                if str(scale) not in ALLOWED_TPCH_SCALES:
                    self._error(rel_path, f"{manifest_id}: unsupported tpch scale {scale!r}")
            elif name == "job":
                if str(scale) not in ALLOWED_JOB_SCALES:
                    self._error(rel_path, f"{manifest_id}: unsupported job scale {scale!r}")

    def _validate_v3_lineage(
        self,
        rel_path: str,
        manifest_id: str,
        successor: Mapping[str, Any],
        lineage: Any,
    ) -> None:
        if not isinstance(lineage, Mapping):
            self._error(rel_path, f"{manifest_id}: v3 manifest requires lineage mapping")
            return
        for field in ("predecessor_path", "predecessor_sha256", "migration"):
            if not lineage.get(field):
                self._error(rel_path, f"{manifest_id}: lineage missing {field}")
        predecessor_hash = lineage.get("predecessor_sha256")
        if predecessor_hash and not SHA256_RE.match(str(predecessor_hash)):
            self._error(
                rel_path,
                f"{manifest_id}: lineage.predecessor_sha256 must be a sha256 digest",
            )
        predecessor_path = lineage.get("predecessor_path")
        if predecessor_path:
            predecessor = self.root / str(predecessor_path)
            if not predecessor.is_file():
                self._error(
                    rel_path,
                    f"{manifest_id}: lineage predecessor is missing: {predecessor_path}",
                )
            elif predecessor_hash and file_sha256(predecessor) != predecessor_hash:
                self._error(
                    rel_path,
                    f"{manifest_id}: lineage predecessor hash does not match",
                )
            else:
                try:
                    predecessor_data = load_yaml(predecessor)
                except (OSError, yaml.YAMLError) as exc:
                    self._error(
                        rel_path,
                        f"{manifest_id}: cannot read lineage predecessor: {exc}",
                    )
                else:
                    if isinstance(predecessor_data, Mapping):
                        self._validate_v3_successor_equivalence(
                            rel_path, manifest_id, successor, predecessor_data
                        )
                    else:
                        self._error(
                            rel_path,
                            f"{manifest_id}: lineage predecessor must be a mapping",
                        )

    def _validate_v3_successor_equivalence(
        self,
        rel_path: str,
        manifest_id: str,
        successor: Mapping[str, Any],
        predecessor: Mapping[str, Any],
    ) -> None:
        expected_manifest_id = f"{predecessor.get('manifest_id')}_taxonomy_v3"
        if manifest_id != expected_manifest_id:
            self._error(
                rel_path,
                f"{manifest_id}: expected successor manifest_id {expected_manifest_id!r}",
            )

        successor_modes = _as_list(successor.get("modes"))
        predecessor_modes = _as_list(predecessor.get("modes"))
        try:
            normalized_successor_modes = [normalize_mode_id(str(mode)) for mode in successor_modes]
            normalized_predecessor_modes = [
                normalize_mode_id(str(mode)) for mode in predecessor_modes
            ]
        except ValueError as exc:
            self._error(rel_path, f"{manifest_id}: {exc}")
        else:
            if normalized_successor_modes != normalized_predecessor_modes:
                self._error(
                    rel_path,
                    f"{manifest_id}: v3 mode order/membership differs from predecessor",
                )

        successor_outputs = successor.get("outputs")
        predecessor_outputs = predecessor.get("outputs")
        if isinstance(successor_outputs, Mapping) and isinstance(
            predecessor_outputs, Mapping
        ):
            expected_outputs = {
                key: (
                    str(value).replace("results/", "results/v3/", 1)
                    if str(value).startswith("results/")
                    else value
                )
                for key, value in predecessor_outputs.items()
            }
            if dict(successor_outputs) != expected_outputs:
                self._error(
                    rel_path,
                    f"{manifest_id}: v3 outputs must preserve predecessor paths "
                    "under results/v3/",
                )
        elif successor_outputs != predecessor_outputs:
            self._error(rel_path, f"{manifest_id}: v3 outputs differ from predecessor")

        successor_core = dict(successor)
        predecessor_core = dict(predecessor)
        for field in ("manifest_schema", "lineage", "manifest_id", "modes", "outputs"):
            successor_core.pop(field, None)
            predecessor_core.pop(field, None)
        if self._canonicalize_v3_successor_value(
            successor_core
        ) != self._canonicalize_v3_successor_value(predecessor_core):
            self._error(
                rel_path,
                f"{manifest_id}: scientific fields differ from lineage predecessor",
            )

    @classmethod
    def _canonicalize_v3_successor_value(cls, value: Any) -> Any:
        """Normalize only the two permitted recursive successor migrations."""

        if isinstance(value, Mapping):
            return {
                key: cls._canonicalize_v3_successor_value(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._canonicalize_v3_successor_value(item) for item in value]
        if isinstance(value, str):
            if value in {
                LEGACY_CONTRACT_AWARE_MODE,
                LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
            }:
                return normalize_mode_id(value)
            if value == "comparator_over_contract_aware":
                return "comparator_over_admission_first"
            for prefix in (
                "results/v3/raw/",
                "results/v3/summarized/",
                "results/v3/analysis/",
            ):
                if value.startswith(prefix):
                    return value.replace("results/v3/", "results/", 1)
        return value

    def _validate_manifest_modes(
        self,
        rel_path: str,
        manifest_id: str,
        modes: Sequence[Any],
        *,
        require_canonical: bool,
    ) -> None:
        if not modes:
            self._warning(rel_path, f"{manifest_id}: no modes declared")
            return

        for raw_mode in modes:
            mode = str(raw_mode)
            try:
                canonical_mode = normalize_mode_id(mode)
            except ValueError:
                self._error(rel_path, f"{manifest_id}: unknown mode {mode!r}")
                continue
            if require_canonical and canonical_mode != mode:
                self._error(
                    rel_path,
                    f"{manifest_id}: v3 manifest uses legacy mode id {mode!r}",
                )
            if canonical_mode not in self._glossary_modes:
                self._error(
                    rel_path,
                    f"{manifest_id}: mode {mode!r} absent from glossary",
                )
            if canonical_mode not in self._api_modes:
                self._error(
                    rel_path,
                    f"{manifest_id}: mode {mode!r} absent from baseline API",
                )
            spec = self._mode_registry.get(canonical_mode)
            if spec is None:
                self._error(rel_path, f"{manifest_id}: mode {mode!r} lacks evaluation_role")
            elif spec.evaluation_role not in ALLOWED_EVALUATION_ROLES:
                self._error(
                    rel_path,
                    f"{manifest_id}: mode {mode!r} invalid evaluation_role "
                    f"{spec.evaluation_role!r}",
                )

    def _validate_query_paths(
        self, rel_path: str, manifest_id: str, data: Mapping[str, Any]
    ) -> None:
        for query in _as_list(data.get("queries")):
            if not isinstance(query, Mapping):
                self._error(rel_path, f"{manifest_id}: query entry must be an object")
                continue
            query_path = query.get("path")
            query_id = query.get("query_id", "<unknown>")
            if not query_path:
                self._error(rel_path, f"{manifest_id}: query {query_id} missing path")
                continue
            if not (self.root / str(query_path)).exists():
                self._error(rel_path, f"{manifest_id}: query path missing: {query_path}")

    def _validate_policy_applications(
        self, rel_path: str, manifest_id: str, data: Mapping[str, Any]
    ) -> None:
        applications = _as_list(data.get("policy_applications"))
        for application in applications:
            if not isinstance(application, Mapping):
                self._error(rel_path, f"{manifest_id}: policy application must be an object")
                continue
            policy_id = str(application.get("policy_id", ""))
            relation = str(application.get("relation", ""))
            if not policy_id or not relation:
                self._error(
                    rel_path,
                    f"{manifest_id}: policy application needs policy_id and relation",
                )
                continue
            policy = self._policy_catalog.get(policy_id)
            if policy is None:
                self._error(rel_path, f"{manifest_id}: unknown policy_id {policy_id}")
                continue
            applicable = set(_as_list(policy.get("applicable_relations")))
            if relation not in applicable:
                self._error(
                    rel_path,
                    f"{manifest_id}: policy {policy_id} not applicable to {relation}",
                )

    def _validate_template_applicability(
        self, rel_path: str, manifest_id: str, data: Mapping[str, Any]
    ) -> None:
        candidates = {str(candidate) for candidate in _as_list(data.get("template_candidates"))}
        if not candidates:
            return

        unknown = candidates - KNOWN_TEMPLATE_CANDIDATES
        for candidate in sorted(unknown):
            self._error(rel_path, f"{manifest_id}: unknown template_candidate {candidate!r}")

        variables = data.get("variables") or {}
        artifact_availability = set(_as_list(variables.get("artifact_availability")))
        has_artifact_gap = bool(candidates & ARTIFACT_TEMPLATES) and (
            "none" in artifact_availability or "auth_idx" not in artifact_availability
        )
        if not has_artifact_gap:
            return

        policy = data.get("applicability_policy")
        if not isinstance(policy, Mapping):
            self._error(
                rel_path,
                f"{manifest_id}: artifact-dependent template candidates need "
                "applicability_policy",
            )
            return
        expected = "record_template_applicability_artifact_unavailable"
        if policy.get("artifact_missing") != expected:
            self._error(
                rel_path,
                f"{manifest_id}: artifact_missing must be {expected}",
            )

    def _validate_outputs(
        self,
        rel_path: str,
        manifest_id: str,
        data: Mapping[str, Any],
        *,
        require_v3_namespace: bool,
    ) -> None:
        outputs = data.get("outputs")
        if outputs is None:
            return
        if not isinstance(outputs, Mapping):
            self._error(rel_path, f"{manifest_id}: outputs must be an object")
            return
        for field in ("raw_dir", "summary_dir"):
            value = outputs.get(field)
            if value is None:
                self._error(rel_path, f"{manifest_id}: outputs missing {field}")
                continue
            required_prefix = "results/v3/" if require_v3_namespace else "results/"
            if not str(value).startswith(required_prefix):
                self._error(
                    rel_path,
                    f"{manifest_id}: outputs.{field} must be under {required_prefix}",
                )

    def _validate_manifest_specific_contracts(
        self, rel_path: str, manifest_id: str, data: Mapping[str, Any]
    ) -> None:
        experiment = str(data.get("experiment", ""))
        execution_tier = data.get("execution_tier")
        if execution_tier == "smoke" and data.get("ae_required") is not True:
            self._error(rel_path, f"{manifest_id}: smoke manifests must set ae_required: true")

        if experiment == "E6" and execution_tier == "smoke":
            components = {str(item) for item in _as_list(data.get("ablation_components"))}
            missing = REQUIRED_E6A_COMPONENTS - components
            extra = components - REQUIRED_E6A_COMPONENTS
            for component in sorted(missing):
                self._error(rel_path, f"{manifest_id}: missing E6a component {component}")
            for component in sorted(extra):
                self._error(rel_path, f"{manifest_id}: unknown E6a component {component}")

        if experiment == "E8" and execution_tier == "smoke":
            scenarios = _as_list(data.get("scenarios"))
            if not scenarios:
                self._error(rel_path, f"{manifest_id}: E8a smoke must declare scenarios")
            for scenario in scenarios:
                if not isinstance(scenario, Mapping):
                    self._error(rel_path, f"{manifest_id}: scenario must be an object")
                    continue
                if not scenario.get("id"):
                    self._error(rel_path, f"{manifest_id}: scenario missing id")
                action = scenario.get("expected_action")
                if action not in ALLOWED_ARTIFACT_ACTIONS:
                    self._error(
                        rel_path,
                        f"{manifest_id}: scenario {scenario.get('id')} has invalid "
                        f"expected_action {action!r}",
                    )

        if experiment == "E3" and data.get("stage") in {"smoke", "standard_workloads_reduced"}:
            expected_scales = {"tpch": REDUCED_TPCH_SCALE, "job": REDUCED_JOB_SCALE}
            for dataset in _as_list(data.get("datasets")):
                if not isinstance(dataset, Mapping):
                    continue
                name = str(dataset.get("name", ""))
                expected = expected_scales.get(name)
                if expected is not None and str(dataset.get("scale")) != expected:
                    self._error(
                        rel_path,
                        f"{manifest_id}: reduced E3 dataset {name} must use scale {expected!r}",
                    )

        if experiment == "E6" and data.get("stage") == "sigma_full":
            expected_scales = {"tpch": "SF10", "job": "full"}
            for dataset in _as_list(data.get("datasets")):
                if not isinstance(dataset, Mapping):
                    continue
                name = str(dataset.get("name", ""))
                expected = expected_scales.get(name)
                if expected is not None and str(dataset.get("scale")) != expected:
                    self._error(
                        rel_path,
                        f"{manifest_id}: E6b dataset {name} must use scale {expected!r}",
                    )

        if experiment == "E9" and execution_tier == "smoke":
            generator = data.get("synthetic_generator")
            tiers = data.get("tiers")
            if not isinstance(generator, Mapping):
                self._error(rel_path, f"{manifest_id}: E9 smoke missing synthetic_generator")
            if not isinstance(tiers, list) or not tiers:
                self._error(rel_path, f"{manifest_id}: E9 smoke missing tiers")

    def _validate_required_smoke_surface(
        self, experiment_records: Sequence[Tuple[Path, Mapping[str, Any]]]
    ) -> None:
        smoke_by_experiment: Dict[str, List[str]] = {}
        for path, data in experiment_records:
            if data.get("execution_tier") != "smoke":
                continue
            experiment = str(data.get("experiment", ""))
            smoke_by_experiment.setdefault(experiment, []).append(str(data.get("manifest_id", path)))

        for experiment in sorted(REQUIRED_SMOKE_EXPERIMENTS):
            if experiment not in smoke_by_experiment:
                self._error(
                    "manifests/experiments",
                    f"missing required smoke manifest for {experiment}",
                )

    def _error(self, path: str, message: str) -> None:
        self.errors.append(ValidationIssue(level="error", path=path, message=message))

    def _warning(self, path: str, message: str) -> None:
        self.warnings.append(ValidationIssue(level="warning", path=path, message=message))
