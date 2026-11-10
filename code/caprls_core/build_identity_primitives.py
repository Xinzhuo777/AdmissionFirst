"""Build optional exact-identity primitives with the current CPython toolchain.

Run: python -m caprls_core.build_identity_primitives
No packages are installed and no network access or downloaded code is needed.
"""
import hashlib
import json
from pathlib import Path
import sys
import sysconfig
import tempfile


def main():
    if sys.implementation.name != "cpython":
        raise RuntimeError("native primitives require CPython; use the Python fallback")
    from setuptools._distutils.ccompiler import new_compiler
    from setuptools._distutils.sysconfig import customize_compiler
    root = Path(__file__).resolve().parents[1]
    source = root / "planner/_identity_primitives.c"
    binary = root / ("planner/_identity_primitives" + sysconfig.get_config_var("EXT_SUFFIX"))
    compiler = new_compiler()
    customize_compiler(compiler)
    with tempfile.TemporaryDirectory(prefix="caprls_identity_build_") as temporary:
        objects = compiler.compile([str(source)], output_dir=temporary,
                                   include_dirs=[sysconfig.get_path("include")],
                                   extra_postargs=["-O3"])
        compiler.link_shared_object(objects, str(binary))
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {"schema": "identity_primitives_build_v1",
                "python_cache_tag": sys.implementation.cache_tag,
                "soabi": sysconfig.get_config_var("SOABI"),
                "python_version": sys.version, "platform": sysconfig.get_platform(),
                "source_path": str(source.relative_to(root)), "source_sha256": sha(source),
                "binary_path": str(binary.relative_to(root)), "binary_sha256": sha(binary),
                "compiler": compiler.compiler, "linker": compiler.linker_so,
                "extra_compile_flags": ["-O3"], "gil_released": False,
                "scope": "Exact primitive identity comparisons only; no cached admission or authorization verdict."}
    target = root / "configs/identity_primitives_build.yaml"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
