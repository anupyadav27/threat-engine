"""
check_runner.py — Phase 1 Golden-Set Validation Harness

Imports every golden check, runs PASS/FAIL fixture assertions, and
prints a summary. Exits non-zero if any check fails.

Usage:
    python golden/check_runner.py
    python golden/check_runner.py --emit-yaml     # also print YAML specs
    python golden/check_runner.py --csp aws       # only one CSP
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
GOLDEN_DIR = Path(__file__).parent

# Ordered list of (csp, filename) for all 30 golden checks
CHECKS = [
    # AWS
    ("aws",      "aws_01_scalar_exists"),
    ("aws",      "aws_02_nested_multi_all"),
    ("aws",      "aws_03_array_not_contains"),
    ("aws",      "aws_04_boolean_equals_false"),
    ("aws",      "aws_05_numeric_threshold"),
    # Azure
    ("azure",    "azure_01_equals_true"),
    ("azure",    "azure_02_nested_boolean"),
    ("azure",    "azure_03_in_list"),
    ("azure",    "azure_04_not_empty"),
    ("azure",    "azure_05_array_not_equals"),
    # GCP
    ("gcp",      "gcp_01_boolean_is_false"),
    ("gcp",      "gcp_02_scalar_equals"),
    ("gcp",      "gcp_03_deep_nested_exists"),
    ("gcp",      "gcp_04_array_all_condition"),
    ("gcp",      "gcp_05_array_filter_not_contains"),
    # OCI
    ("oci",      "oci_01_scalar_exists"),
    ("oci",      "oci_02_scalar_equals"),
    ("oci",      "oci_03_nested_path"),
    ("oci",      "oci_04_length_gte"),
    ("oci",      "oci_05_not_empty"),
    # K8s
    ("k8s",      "k8s_01_boolean_is_false"),
    ("k8s",      "k8s_02_array_not_empty"),
    ("k8s",      "k8s_03_not_equals_wildcard"),
    ("k8s",      "k8s_04_annotation_exists"),
    ("k8s",      "k8s_05_readonly_rootfs"),
    # AliCloud
    ("alicloud", "alicloud_01_scalar_exists"),
    ("alicloud", "alicloud_02_equals_true"),
    ("alicloud", "alicloud_03_nested_exists"),
    ("alicloud", "alicloud_04_array_not_contains"),
    ("alicloud", "alicloud_05_scalar_equals_enum"),
]


def load_module(csp: str, name: str):
    path = GOLDEN_DIR / csp / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-yaml", action="store_true", help="Print YAML spec for each check")
    parser.add_argument("--csp", default=None, help="Limit to one CSP (aws/azure/gcp/oci/k8s/alicloud)")
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT))
    from python_to_yaml_generator import run_golden, emit_yaml

    passed = failed = 0
    current_csp = None

    for csp, name in CHECKS:
        if args.csp and csp != args.csp:
            continue

        if csp != current_csp:
            print(f"\n{'─' * 60}")
            print(f"  {csp.upper()}")
            print(f"{'─' * 60}")
            current_csp = csp

        try:
            mod = load_module(csp, name)
            gc  = mod.GOLDEN
            ok  = run_golden(gc, verbose=True)
            if args.emit_yaml:
                print(emit_yaml(gc.spec))
            if ok:
                passed += 1
            else:
                failed += 1
        except Exception as exc:
            print(f"  [✗] {csp}/{name}  ERROR: {exc}")
            failed += 1

    print(f"\n{'═' * 60}")
    print(f"  Results: {passed} passed / {failed} failed / {passed + failed} total")
    print(f"{'═' * 60}\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
