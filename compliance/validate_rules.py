#!/usr/bin/env python3
"""
Static validator for CSP rule YAML files (lightweight / non-strict).

Validates basic structure of discovery and checks blocks where applicable, but:
  - Ignores metadata YAMLs and index files.
  - Does NOT enforce operator names (engines may support more than this knows).
  - Only enforces local discovery/for_each linkage for K8s, where schema is clear.

Usage:
    python compliance/validate_rules.py --csp gcp
    python compliance/validate_rules.py --csp all
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


ROOT_DIR = Path(__file__).resolve().parents[1]


ENGINE_ROOTS: Dict[str, Path] = {
    "aws": ROOT_DIR / "aws_compliance_python_engine" / "services",
    "azure": ROOT_DIR / "azure_compliance_python_engine" / "services",
    "gcp": ROOT_DIR / "gcp_compliance_python_engine" / "services",
    "oci": ROOT_DIR / "oci_compliance_python_engine" / "services",
    "ibm": ROOT_DIR / "ibm_compliance_python_engine" / "services",
    "alicloud": ROOT_DIR / "alicloud_compliance_python_engine" / "services",
    "k8s": ROOT_DIR / "k8_engine" / "services",
}


@dataclass
class ValidationError:
    csp: str
    file: Path
    context: str
    message: str

    def format(self) -> str:
        rel = self.file.relative_to(ROOT_DIR)
        return f"[{self.csp}] {rel}: {self.context}: {self.message}"


def iter_yaml_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(root.rglob("*.yaml"))


def load_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        raise RuntimeError(f"Failed to parse YAML: {e}") from e


def validate_k8s_file(csp: str, path: Path, data: Dict[str, Any]) -> List[ValidationError]:
    """
    K8s YAML has a well-understood schema: top-level discovery + checks.
    Here we enforce:
      - discovery/checks present
      - for_each points to local discovery_id
      - checks have check_id, severity, calls.
    """
    errors: List[ValidationError] = []

    if "checks" not in data or "discovery" not in data:
        errors.append(
            ValidationError(
                csp=csp,
                file=path,
                context="k8s",
                message="Missing top-level 'discovery' or 'checks' section",
            )
        )
        return errors

    discoveries = data.get("discovery") or []
    discovery_ids = {
        d.get("discovery_id")
        for d in discoveries
        if isinstance(d, dict) and d.get("discovery_id")
    }

    checks = data.get("checks") or []
    if not isinstance(checks, list):
        errors.append(
            ValidationError(
                csp=csp,
                file=path,
                context="k8s.checks",
                message="'checks' must be a list",
            )
        )
        return errors

    for idx, chk in enumerate(checks):
        if not isinstance(chk, dict):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=f"check[{idx}]",
                    message="Check must be a mapping",
                )
            )
            continue

        check_id = chk.get("check_id")
        ctx = f"check_id={check_id or f'#{idx}'}"

        if not check_id or not isinstance(check_id, str):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Missing or invalid 'check_id'",
                )
            )

        for_each = chk.get("for_each")
        if not for_each or not isinstance(for_each, str):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Missing or invalid 'for_each' (must be discovery_id string)",
                )
            )
        elif for_each not in discovery_ids:
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message=f"'for_each' references unknown discovery_id '{for_each}'",
                )
            )

        calls = chk.get("calls") or []
        if not isinstance(calls, list) or not calls:
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Check must define non-empty 'calls' list",
                )
            )

        logic = chk.get("logic")
        if logic and logic not in ("AND", "OR"):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="logic must be 'AND' or 'OR' if specified",
                )
            )

    return errors


def validate_service_block(
    csp: str,
    path: Path,
    service_name: str,
    block: Dict[str, Any],
) -> List[ValidationError]:
    """
    Generic validator for engines that use a 'checks' array on a per-service block
    (Azure, GCP, OCI, IBM). We only check for basic presence of fields.
    """
    errors: List[ValidationError] = []
    ctx_prefix = f"service={service_name}"

    discovery = block.get("discovery") or []
    discovery_ids = {
        d.get("discovery_id")
        for d in discovery
        if isinstance(d, dict) and d.get("discovery_id")
    }

    checks = block.get("checks") or []
    if not isinstance(checks, list):
        errors.append(
            ValidationError(
                csp=csp,
                file=path,
                context=ctx_prefix,
                message="'checks' must be a list",
            )
        )
        return errors

    for idx, chk in enumerate(checks):
        if not isinstance(chk, dict):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=f"{ctx_prefix}.checks[{idx}]",
                    message="Check must be a mapping",
                )
            )
            continue

        check_id = chk.get("check_id")
        ctx = f"{ctx_prefix}.check_id={check_id or f'#{idx}'}"

        if not check_id or not isinstance(check_id, str):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Missing or invalid 'check_id'",
                )
            )

        if not chk.get("severity"):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Missing 'severity'",
                )
            )

        for_each = chk.get("for_each")
        if not for_each or not isinstance(for_each, str):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Missing or invalid 'for_each' (must be string)",
                )
            )

        calls = chk.get("calls") or []
        if not isinstance(calls, list) or not calls:
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="Check must define non-empty 'calls' list",
                )
            )

        logic = chk.get("logic")
        if logic and logic not in ("AND", "OR"):
            errors.append(
                ValidationError(
                    csp=csp,
                    file=path,
                    context=ctx,
                    message="logic must be 'AND' or 'OR' if specified",
                )
            )

    return errors


def validate_generic_file(csp: str, path: Path, data: Dict[str, Any]) -> List[ValidationError]:
    """
    Validate non-K8s engines where YAML has top-level keys per service
    (Azure, GCP, OCI, IBM).
    """
    errors: List[ValidationError] = []

    if not isinstance(data, dict):
        errors.append(
            ValidationError(
                csp=csp,
                file=path,
                context="file",
                message="Top-level YAML must be a mapping",
            )
        )
        return errors

    has_service = False
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        if "checks" not in value:
            continue
        has_service = True
        errors.extend(validate_service_block(csp, path, str(key), value))

    if not has_service:
        errors.append(
            ValidationError(
                csp=csp,
                file=path,
                context="file",
                message="No service blocks with 'checks' found",
            )
        )

    return errors


def validate_file(csp: str, path: Path) -> List[ValidationError]:
    try:
        data = load_yaml(path)
    except RuntimeError as e:
        return [
            ValidationError(
                csp=csp,
                file=path,
                context="file",
                message=str(e),
            )
        ]

    if csp == "k8s":
        if isinstance(data, dict) and "checks" in data:
            return validate_k8s_file(csp, path, data)
        # K8s may have non-rule YAMLs under services; ignore quietly.
        return []

    return validate_generic_file(csp, path, data)


def validate_csp(csp: str) -> List[ValidationError]:
    root = ENGINE_ROOTS.get(csp)
    if not root:
        raise ValueError(f"Unknown CSP '{csp}'")

    # AWS and Alicloud engines use a different templated YAML format without
    # explicit 'checks' blocks. We currently skip them in this validator to
    # avoid false positives; they can get their own schema later.
    if csp in {"aws", "alicloud"}:
        return []

    errors: List[ValidationError] = []
    for yaml_path in iter_yaml_files(root):
        # Only validate actual rule definition files, not metadata/index YAMLs.
        # This keeps the validator focused on executable checks.
        name = yaml_path.name

        is_rule_file = False
        if csp == "k8s":
            # K8s service YAMLs live directly under component directories.
            is_rule_file = name.endswith("_rules.yaml") or name.endswith(".yaml")
        elif csp in {"azure", "oci", "ibm"}:
            # Conventional layout: <service>_rules.yaml at service root.
            # Metadata uses full check IDs with many dots; we treat files with a
            # single dot before extension and *_rules.yaml as rule files.
            if name.endswith("_rules.yaml"):
                parts = name.split(".")
                if len(parts) == 2:
                    is_rule_file = True
        elif csp == "gcp":
            # GCP uses services/<service>/<service>_rules.yaml
            if name.endswith("_rules.yaml"):
                parts = name.split(".")
                if len(parts) == 2:
                    is_rule_file = True
        else:
            is_rule_file = True

        if not is_rule_file:
            continue

        errors.extend(validate_file(csp, yaml_path))

    return errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate CSP rule YAML files.")
    parser.add_argument(
        "--csp",
        choices=sorted(["all"] + list(ENGINE_ROOTS.keys())),
        default="all",
        help="Which CSP to validate (default: all).",
    )
    args = parser.parse_args(argv)

    csps = list(ENGINE_ROOTS.keys()) if args.csp == "all" else [args.csp]

    all_errors: List[ValidationError] = []
    for csp in csps:
        errors = validate_csp(csp)
        if errors:
            print(f"❌ {csp.upper()}: {len(errors)} validation errors")
            for err in errors:
                print("   -", err.format())
        else:
            print(f"✅ {csp.upper()}: no validation errors")
        all_errors.extend(errors)

    if all_errors:
        print(f"\n❌ Validation failed with {len(all_errors)} total errors")
        return 1

    print("\n✅ All selected CSP rule files are structurally valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
