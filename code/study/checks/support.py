"""Preserved paired interface, pinned to selected A016 R02; no PG on import.

Selection and execution stay in the frozen source's existing worker. This
module resolves its declaration, audits the original returned decision, and
exposes only the validated effective layout to the older support checks.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

from scope_support import bound_core, source_parser


PAIRED_SOURCE_DIGEST = "sha256:6ef380ed6cb9eca8e62cc3046f3ec458a9498c6268c45299f81d52d205cecd93"
STUDY_SHA = "sha256:d6de0ada36a54cb8f2a993ac5239bc0a6276d761415c07f2345242a221119771"
FORMAL_SHA = "sha256:3007751c875f97ed2de362cad0cd2457fe17aba9b3d20f7b5180f68524f51f1c"
AUDIT_HELPER_SHA = "sha256:52bcd9d9df75e8f21f0b162a4aae05f9e5a316d251a120988535614969e5c4c6"
STRATEGY = "strong_handoff_min_full_cost_v1"
DEFAULT_SOURCE = "."
DEFAULT_MANIFEST = "study/inputs/mixed-input-manifest.yaml"


def sha(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("support module is unavailable: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PairedSupport:
    def __init__(self, root, source, extra_files=()):
        self.root, self.source = Path(root).resolve(), Path(source).resolve()
        study_path = self.source / "caprls_core/final_af_e3_study.py"
        formal_path = self.source / "caprls_core/final_af_e3_analyze.py"
        if sha(study_path) != STUDY_SHA or sha(formal_path) != FORMAL_SHA:
            raise ValueError("support bridge requires the frozen paired R08 worker/auditor")
        self.study = load_file("_support_r08_frozen_study", study_path)
        self.identity = self.study.source_identity(self.source)
        original = json.loads((self.root / "study/source-freeze.json").read_text())["source_identity"]["files"]
        observed = dict(self.identity["files"])
        original = dict(original)
        observed.pop("configs/identity_primitives_build.yaml", None)
        original.pop("configs/identity_primitives_build.yaml", None)
        if observed != original or sha(self.source / "planner/_identity_primitives.c") != "sha256:45c98da081327e07b902a7fdc865b3cc3eb137f14c1867b8c2fb8a5b7d60f375":
            raise ValueError("support bridge source differs from frozen experiment")
        native_manifest_path = self.source / "configs/identity_primitives_build.yaml"
        native_manifest = json.loads(native_manifest_path.read_text())
        self.native_backend = {
            "name": "native-primitives", "reason": "verified_build",
            "source_sha256": native_manifest["source_sha256"],
            "binary_sha256": native_manifest["binary_sha256"],
            "build_manifest_sha256": sha(native_manifest_path).split(":", 1)[1],
            "python_cache_tag": native_manifest["python_cache_tag"],
        }
        self.native_paths = (native_manifest_path,
                             self.source / native_manifest["source_path"],
                             self.source / native_manifest["binary_path"])
        if (sha(self.native_paths[1]).split(":", 1)[1] != native_manifest["source_sha256"]
                or sha(self.native_paths[2]).split(":", 1)[1] != native_manifest["binary_sha256"]):
            raise ValueError("selected support native build differs")
        self.declared = self.study.source_physical_recipe_declaration(self.source)
        if (not isinstance(self.declared, dict)
                or self.declared.get("physical_recipe_strategy") != STRATEGY
                or self.declared.get("access_root_wrapper") != "not_materialized_single_reference"
                or self.declared.get("access_root_materialized_by_template") != {"auth_index_enum_v1": True}):
            raise ValueError("support bridge requires the unchanged source recipe declaration")
        self.declared_digest = digest(self.declared)
        paths = (Path(__file__).resolve(), study_path, formal_path, *self.native_paths,
                 Path(__file__).with_name("scope_support.py"),
                 self.source / "planner/pc_scope.py",
                 self.source / "planner/continuation_necessity.py",
                 self.source / "configs/normal_e3_af_candidate.yaml",
                 *(Path(path).resolve() for path in extra_files))
        self.inputs = {str(path): sha(path) for path in paths}
        self._formal = None
        self._archived = set()

    def guard(self):
        if self.study.source_identity(self.source) != self.identity:
            raise ValueError("paired support source changed")
        if any(sha(path) != value for path, value in self.inputs.items()):
            raise ValueError("paired support adapter/input changed")

    def formal(self):
        # Delay canonical imports: the stability driver activates its source
        # first, while CONTENT retains its existing project-side verifier.
        if self._formal is None:
            helper = importlib.import_module("caprls_core.af_pareto_analyze")
            if sha(helper.__file__) != AUDIT_HELPER_SHA:
                raise ValueError("paired support audit helper differs from frozen paired R08")
            with source_parser(self.source):
                self._formal = load_file("_support_r08_frozen_formal",
                                         self.source / "caprls_core/final_af_e3_analyze.py")
        return self._formal

    def protocol_fields(self):
        return {
            "physical_recipe_strategy": STRATEGY,
            "declared_runtime_config": json.loads(json.dumps(self.declared)),
            "declared_runtime_config_sha256": self.declared_digest,
            "access_root_wrapper": self.declared["access_root_wrapper"],
            "access_root_wrapper_override": None,
            "access_root_materialized_by_template": dict(self.declared["access_root_materialized_by_template"]),
            "access_root_materialized_by_template_override": None,
            "access_root_wrapper_resolution": "source_normal_physical_recipe_strategy",
            "normal_entry_execution_check": True,
            "normal_entry_execution_scope": "one extra guarded exact body per support observation; no query-latency benchmark",
            "support_r02_adapter": "external_declared_to_validated_effective_v1",
            "identity_observation_backend_required": self.native_backend,
            "user_runtime_overrides": None,
        }

    def recover_core(self, sql, bound):
        with source_parser(self.source) as parser:
            return bound_core(sql, bound, parser)

    def root_materialized(self, sql):
        with source_parser(self.source) as parser:
            value = parser.decode_access_root_materialized(sql)
        if value is None:
            raise ValueError("support runner lacks its canonical access-root composition")
        return value

    def validate_worker(self, packet, request):
        if (packet.get("source_identity") != self.identity
                or packet.get("manifest_sha256") != sha(request["manifest"])):
            raise ValueError("paired support worker source/manifest differs")
        self.study.validate_af_bound_spec(packet)
        spec, selection = packet["spec"], packet["selection"]
        metadata = selection.get("normal_entry_metadata") or {}
        if metadata.get("identity_observation_backend") != self.native_backend:
            raise ValueError("selected support worker did not use the verified native backend")
        if (selection.get("normal_entry_used") is not True
                or metadata.get("declared_runtime_config") != self.declared
                or metadata.get("declared_runtime_config_sha256") != self.declared_digest
                or metadata.get("source_identity") != self.identity):
            raise ValueError("paired support did not use its unchanged normal source declaration")
        # The pinned worker calls normal.prepared_report before exporting these
        # fields. Retain/validate its original mirror; never alter a spec/map.
        physical = metadata.get("physical_recipe_selection")
        if (not isinstance(physical, dict)
                or selection.get("physical_recipe_selection") != physical
                or selection.get("physical_recipe_strategy") != STRATEGY):
            raise ValueError("paired support lacks the owned-replayed physical diagnostic mirror")
        formal = self.formal()
        protocol = {**self.protocol_fields(), "current_source": self.identity,
                    "manifest": str(Path(request["manifest"]).resolve()),
                    "manifest_sha256": packet["manifest_sha256"]}
        label = request["query_id"] + "__" + request["policy_id"]
        effective, physical_check = formal.physical_recipe_protocol_audit(
            protocol, spec, selection, query=request["query_id"],
            policy=request["policy_id"], label=label)
        profile = formal.execution_profile_audit(
            spec, selection, query=request["query_id"], policy=request["policy_id"],
            pg_env=request["pg_env"], required_profile="trusted_explicit", label=label)
        normal = formal.normal_entry_audit(
            effective, spec, selection, profile, query=request["query_id"],
            policy=request["policy_id"], label=label)
        wrapper = formal.access_root_wrapper_audit(
            effective, spec["sql"], label, template_id=spec["template_id"])
        layout = formal.access_root_layout_policy_audit(effective, selection, wrapper, label)
        return {
            "physical_recipe": physical_check, "normal": normal,
            "wrapper": wrapper, "layout": layout,
            "effective_base_materialized": effective["access_root_wrapper"] == "materialized",
            "effective_materialized_by_template": dict(effective["access_root_materialized_by_template"]),
            "declared_runtime_config_sha256": self.declared_digest,
        }

    def run_worker(self, request, timeout_s=1800):
        self.guard()
        if (request.get("access_root_materialized") is not False
                or request.get("access_root_materialized_by_template") != self.declared["access_root_materialized_by_template"]
                or request.get("worker_kind") != "af" or request.get("variant") != "af"):
            raise ValueError("paired support request conflicts with its source declaration")
        request = {**request, "verify_normal_execution": True,
                   "required_execution_profile": "trusted_explicit"}
        packet = self.study.run_worker(self.source, request, timeout_s=timeout_s)
        checked = self.validate_worker(packet, request)
        self.guard()
        return packet, checked

    def archive(self, output, write):
        output = Path(output).resolve()
        if output in self._archived:
            return
        self.guard()
        write(output / "paired-support-binding.json", {
            "schema": "a016_support_r02_binding_v1", "source": self.identity,
            "declared_runtime_config": self.declared,
            "declared_runtime_config_sha256": self.declared_digest,
            "inputs": self.inputs,
            "ownership_scope": "frozen normal worker performs original owned replay; detached audits do not recreate capabilities",
        })
        folder = output / "paired-adapter-inputs"
        folder.mkdir(parents=True, exist_ok=False)
        for index, path in enumerate(self.inputs):
            with (folder / (str(index) + "-" + Path(path).name)).open("xb") as handle:
                handle.write(Path(path).read_bytes())
        self._archived.add(output)
