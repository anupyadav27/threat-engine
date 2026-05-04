"""Root conftest — sets up import aliases so local tests match Docker environment.

In Docker:
    COPY shared/auth/     → ./engine_auth
    COPY shared/common/   → ./engine_common
    COPY shared/api_gateway/ → ./

Locally we alias those module names to the actual paths.
"""
import sys
import os
import types

_root = os.path.dirname(os.path.abspath(__file__))

# Ensure the shared/ directory subtree is searchable
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "shared"))
sys.path.insert(0, os.path.join(_root, "shared", "api_gateway"))

# Alias engine_auth → shared/auth
import importlib.util as _ilu

def _alias(alias_name: str, real_path: str) -> None:
    """Register a package alias so 'import alias_name' resolves to real_path."""
    if alias_name in sys.modules:
        return
    spec = _ilu.spec_from_file_location(
        alias_name,
        os.path.join(real_path, "__init__.py"),
        submodule_search_locations=[real_path],
    )
    if spec is None:
        return
    mod = _ilu.module_from_spec(spec)
    sys.modules[alias_name] = mod
    spec.loader.exec_module(mod)

    # Also register sub-packages already present on disk
    for entry in os.listdir(real_path):
        sub_path = os.path.join(real_path, entry)
        if os.path.isdir(sub_path) and os.path.exists(os.path.join(sub_path, "__init__.py")):
            sub_alias = f"{alias_name}.{entry}"
            if sub_alias not in sys.modules:
                sub_spec = _ilu.spec_from_file_location(
                    sub_alias,
                    os.path.join(sub_path, "__init__.py"),
                    submodule_search_locations=[sub_path],
                )
                if sub_spec:
                    sub_mod = _ilu.module_from_spec(sub_spec)
                    sys.modules[sub_alias] = sub_mod
                    try:
                        sub_spec.loader.exec_module(sub_mod)
                    except (ImportError, ModuleNotFoundError):
                        # Skip sub-packages with unavailable optional deps (django, etc.)
                        pass
            # Set attribute on parent
            if f"{alias_name}.{entry}" in sys.modules:
                setattr(mod, entry, sys.modules[f"{alias_name}.{entry}"])


_alias("engine_auth", os.path.join(_root, "shared", "auth"))
_alias("engine_common", os.path.join(_root, "shared", "common"))

# Make 'bff' importable directly (for test_auth.py which does `from bff._auth import ...`)
sys.path.insert(0, os.path.join(_root, "shared", "api_gateway"))
