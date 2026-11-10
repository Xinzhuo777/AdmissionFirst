"""Optional, checksum-bound native primitives; Python is the normal fallback."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import sysconfig

_STATUS = {"name": "python", "reason": "not_loaded"}


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_native():
    _STATUS.clear()
    _STATUS.update(name="python", reason="not_loaded")
    if os.environ.get("CAPRLS_IDENTITY_PRIMITIVES", "native") == "python":
        _STATUS.update(reason="explicit_python_fallback")
        return None
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "configs/identity_primitives_build.yaml"
    if not manifest_path.is_file():
        _STATUS.update(reason="no_native_build_manifest")
        return None
    try:
        # JSON is a YAML subset, avoiding an additional import in this path.
        manifest = json.loads(manifest_path.read_text())
        if (manifest.get("schema") != "identity_primitives_build_v1"
                or sys.implementation.name != "cpython"
                or manifest.get("python_cache_tag") != sys.implementation.cache_tag
                or manifest.get("python_version") != sys.version
                or manifest.get("soabi") != sysconfig.get_config_var("SOABI")
                or manifest.get("platform") != sysconfig.get_platform()):
            raise ValueError("native build ABI differs")
        source = (root / manifest["source_path"]).resolve()
        binary = (root / manifest["binary_path"]).resolve()
        source.relative_to(root)
        binary.relative_to(root)
        if (_sha(source) != manifest["source_sha256"]
                or _sha(binary) != manifest["binary_sha256"]):
            raise ValueError("native build bytes differ from its manifest")
        spec = importlib.util.spec_from_file_location("planner._identity_primitives", binary)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _STATUS.update(name="native-primitives", reason="verified_build",
                       source_sha256=manifest["source_sha256"],
                       binary_sha256=manifest["binary_sha256"],
                       build_manifest_sha256=_sha(manifest_path),
                       python_cache_tag=sys.implementation.cache_tag)
        return module
    except (OSError, ValueError, KeyError, ImportError, TypeError, AttributeError) as exc:
        _STATUS.update(reason="native_unavailable", detail=str(exc))
        return None


def backend_info():
    return dict(_STATUS)
