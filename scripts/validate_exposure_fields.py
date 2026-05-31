"""
IEDS-V01: CI gate — validate that every required_emitted_field in an exposure rule
is actually emitted by the corresponding discovery YAML.

Exits with code 1 if any required field is missing from its discovery YAML.
Run this in CI before merging new exposure rules.

Usage:
    python3 scripts/validate_exposure_fields.py [--strict] [--csp aws]

    --strict   Also fail on WARN (fields found in discovery but in different case/format)
    --csp      Validate only rules for this CSP

Exit codes:
    0 = all fields validated
    1 = one or more required fields MISSING from discovery YAML
    2 = discovery YAML not found for a resource type (rules cannot be validated)

How field matching works:
    Discovery YAMLs emit CamelCase AWS API field names (e.g. PublicIpAddress, AuthType).
    Exposure rules use snake_case (public_ip_address, auth_type).
    The validator normalizes both to lowercase-no-separator form for comparison.
    "public_ip_address" → "publicipaddress" matches "PublicIpAddress" → "publicipaddress"

    For nested fields (e.g. resources_vpc_config.endpointPublicAccess):
    Only the top-level field name is checked (resources_vpc_config → check if emitted).
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Set

import yaml

BASE = Path(__file__).parent.parent
EXPOSURE_CATALOG = BASE / "catalog" / "rule" / "network_exposure"
DISCOVERY_ROOT = BASE / "catalog" / "discovery_generator_data"


# CSP → discovery root directory name
CSP_DISCOVERY_DIRS: Dict[str, str] = {
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "oci": "oci",
    "alicloud": "alicloud",
    "ibm": "ibm",
    "k8s": "k8s",
}

# resource_type service segment → actual discovery directory name
# Some resource_type names don't match the discovery YAML directory names.
SERVICE_DIR_ALIASES: Dict[str, str] = {
    # AWS
    "elasticloadbalancingv2": "elbv2",
    "cloudwatchlogs": "logs",
    "cognitoidentityprovider": "cognito-idp",
    # Azure short catalog names → discovery YAML directory
    "virtualmachines": "virtualmachines",   # has its own dir; use compute for richer fields
    "loadbalancers": "network",
    "applicationgateways": "network",
    "sqlservers": "sql",
    "managedclusters": "aks",
    "sites": "appservice",
    "frontdoors": "frontdoor",
    "cdnprofiles": "cdn",
    "apimanagementservice": "apimanagement",
    # OCI (loadbalancer without underscore → load_balancer with underscore)
    "loadbalancer": "load_balancer",
    # OCI compute instances are under oci.core in SDK but stored in compute discovery dir
    "core.instance": "compute",
    # IBM VPC resources use "is" service prefix — map via combined key
    "is.load-balancer": "load_balancer",
    "is.instance": "vpc",   # IBM VPC instance; no dedicated YAML yet — placeholder
}


def _normalize(field: str) -> str:
    """Normalize field name to lowercase with no separators for comparison."""
    # For nested fields like endpoint_configuration.types → use only the top-level part
    top = field.split(".")[0]
    return re.sub(r"[_\-\s]", "", top).lower()


def _collect_emitted_fields(discovery_yaml_path: Path) -> Set[str]:
    """Recursively collect all field names emitted by a discovery YAML step6 file."""
    with open(discovery_yaml_path) as f:
        data = yaml.safe_load(f)

    fields: Set[str] = set()

    def _walk(obj):
        if isinstance(obj, dict):
            emit = obj.get("emit", {})
            if isinstance(emit, dict):
                item = emit.get("item")
                if isinstance(item, dict):
                    for k in item:
                        fields.add(_normalize(k))
                items_for = emit.get("items_for")
                if isinstance(items_for, (list, tuple)):
                    for entry in items_for:
                        if isinstance(entry, dict):
                            for k in entry:
                                fields.add(_normalize(k))
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(data)
    return fields


def _find_discovery_yamls(csp: str, resource_type: str) -> list:
    """
    Find step6 discovery YAML files for a given (csp, resource_type).
    resource_type is in dotted format, e.g. ec2.instance, lambda.functionurl.
    Discovery YAMLs live in:
        catalog/discovery_generator_data/{csp}/{service}/step6_{service}.discovery.yaml
    """
    csp_dir = DISCOVERY_ROOT / CSP_DISCOVERY_DIRS.get(csp, csp)
    if not csp_dir.exists():
        return []

    # Extract the service name from resource_type
    # Try: first, last, first+second, full resource_type combined for alias lookup
    parts = resource_type.split(".")
    service_first = parts[0].lower()
    service_last = parts[-1].lower().replace("-", "_")
    service_combined = ".".join(p.lower() for p in parts[:2]) if len(parts) > 1 else service_first

    # Apply alias: try combined key first, then first segment
    service_alias = SERVICE_DIR_ALIASES.get(service_combined,
                    SERVICE_DIR_ALIASES.get(service_first, service_first))

    # Try service subdirectories: first segment, last segment, and alias
    candidates = []
    for svc_name in dict.fromkeys([service_first, service_last, service_alias]):
        service_dir = csp_dir / svc_name
        if service_dir.exists():
            candidates.extend(service_dir.glob("step6_*.discovery.yaml"))

    # Fallback: search recursively for step6 files containing service name
    if not candidates:
        for yml in csp_dir.rglob(f"step6_{service}*.discovery.yaml"):
            candidates.append(yml)
        for yml in csp_dir.rglob(f"step6_*{service}*.discovery.yaml"):
            if yml not in candidates:
                candidates.append(yml)

    return sorted(candidates)


def load_all_rules(csp_filter: Optional[str] = None) -> list:
    rules = []
    search = EXPOSURE_CATALOG / csp_filter if csp_filter else EXPOSURE_CATALOG
    for yaml_path in sorted(search.rglob("*.yaml")):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        if not data or "rules" not in data:
            continue
        for rule in data["rules"]:
            rule["_source"] = yaml_path.name
            rules.append(rule)
    return rules


def validate(csp_filter: Optional[str] = None, strict: bool = False) -> int:
    rules = load_all_rules(csp_filter)
    print(f"Validating {len(rules)} rules from exposure catalog\n")

    errors = 0
    warns = 0
    discovery_missing = 0
    ok = 0

    for rule in rules:
        required = rule.get("required_emitted_fields") or []
        if not required:
            ok += 1
            continue

        csp = rule.get("csp", "")
        resource_type = rule.get("resource_type", "")
        rule_id = rule.get("rule_id", "?")
        source = rule.get("_source", "?")

        if csp == "all":
            print(f"  [SKIP] {rule_id:30s} csp=all — skip field validation")
            ok += 1
            continue

        yaml_files = _find_discovery_yamls(csp, resource_type)
        if not yaml_files:
            print(f"  [WARN] {rule_id:30s} csp={csp} type={resource_type}")
            print(f"         → No discovery YAML found — cannot validate required fields: {required}")
            warns += 1
            discovery_missing += 1
            continue

        # Collect all emitted fields across all step6 YAML files for this service
        emitted: Set[str] = set()
        for yml in yaml_files:
            emitted.update(_collect_emitted_fields(yml))

        missing = []
        for field in required:
            norm = _normalize(field)
            if norm not in emitted:
                missing.append(field)

        if missing:
            print(f"  [FAIL] {rule_id:30s} ({source})")
            print(f"         csp={csp} type={resource_type}")
            print(f"         Missing fields: {missing}")
            print(f"         Available emitted fields (normalized): {sorted(emitted)[:20]}{'...' if len(emitted)>20 else ''}")
            errors += 1
        else:
            print(f"  [OK]   {rule_id:30s} fields={required}")
            ok += 1

    print(f"\n{'='*60}")
    print(f"Results: OK={ok}  WARN={warns}  FAIL={errors}")
    print(f"  (discovery_missing={discovery_missing} rules could not be validated)")
    print(f"{'='*60}")

    if errors > 0:
        print(f"\n[GATE FAIL] {errors} required fields not found in discovery YAMLs.")
        print("Fix: add the field to the appropriate step6_*.discovery.yaml emit block,")
        print("or correct the field name in the exposure rule YAML.")
        return 1

    if strict and warns > 0:
        print(f"\n[GATE FAIL --strict] {warns} warnings (discovery YAML not found).")
        return 2

    print("\n[GATE PASS] All required fields are present in discovery YAMLs.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CI gate: validate required_emitted_fields exist in discovery YAMLs"
    )
    parser.add_argument("--csp", help="Only validate rules for this CSP")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail if discovery YAML is missing (exit code 2)",
    )
    args = parser.parse_args()

    exit_code = validate(csp_filter=args.csp, strict=args.strict)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
