"""
Package initializer for k8_engine.engine.
Note: There is also a top-level module 'k8_engine/engine.py' which will be
resolved by Python before this package when importing 'k8_engine.engine'.
To import submodules here (e.g., targeted_scan), prefer explicit
'from k8_engine.engine import targeted_scan' only after renaming or
changing the top-level module to avoid name shadowing.
"""
from .engine_main import run_yaml_engine  # noqa: F401 