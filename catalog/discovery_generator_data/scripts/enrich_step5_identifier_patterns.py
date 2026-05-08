#!/usr/bin/env python3
"""
Enrich step5_resource_catalog_inventory_enrich.json with full identifier_pattern strings.

For AWS:  arn:${Partition}:${service}:${Region}:${Account}:${resourceType}/${Id}
For GCP:  projects/{project}/{zone?}/{region?}/{resourceType}/{name}
For Azure: /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
For AliCloud: acs:${service}:${region}:${accountId}:${resourceType}/${Id}
For IBM:  crn:v1:bluemix:public:${service}:${region}:::${resourceType}:${Id}
For OCI:  ocid1.${resourceType}.oc1.${realm}.${uniqueId}

Sources used:
  - Per-service identifier stubs: arn_identifier.json / ocid_identifier.json / crn_identifier.json
  - resource_arn_mapping.json (AWS only — has arn_entity names)
  - Constructed templates as fallback

Run:  python3 scripts/enrich_step5_identifier_patterns.py [--csp aws|gcp|azure|alicloud|ibm|oci]
"""

import argparse
import json
import re
from pathlib import Path

BASE = Path(__file__).parent.parent


# ── Pattern builders ──────────────────────────────────────────────────────────

def _pascal_to_kebab(s: str) -> str:
    """CapacityReservation → capacity-reservation"""
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"-\1", s).lower()


def _snake_to_pascal(s: str) -> str:
    """capacity_reservation → CapacityReservation"""
    return "".join(p.capitalize() for p in s.split("_") if p)


def _infer_aws_pattern(service: str, resource_type: str, identifier: dict) -> str:
    """Build best-effort AWS ARN pattern."""
    primary_param = identifier.get("primary_param", "ResourceId")
    id_type = identifier.get("identifier_type", "arn")

    # Derive resource segment: snake_case → kebab-case
    # resource_type like 'instance_instance' → take last meaningful part
    parts = resource_type.split("_")
    # Remove duplicates (e.g. capacity_reservation_capacity_reservation → capacity_reservation)
    seen = []
    for p in parts:
        if not seen or p != seen[-1]:
            seen.append(p)
    resource_seg = "-".join(seen)

    # Global services (no region)
    global_services = {"iam", "route53", "cloudfront", "waf", "s3"}
    region_part = "" if service in global_services else "${Region}"
    account_part = "${Account}"

    if id_type == "arn":
        return (
            f"arn:${{Partition}}:{service}:{region_part}:{account_part}:"
            f"{resource_seg}/${{{primary_param}}}"
        )
    elif id_type == "id":
        return f"{{{primary_param}}}"
    else:
        return f"{{{primary_param}}}"


def _infer_gcp_pattern(service: str, resource_type: str, identifier: dict) -> str:
    """Build best-effort GCP resource name pattern."""
    tmpl = identifier.get("full_identifier", {}).get("template", "")
    if tmpl:
        return tmpl
    parts = identifier.get("parts", [])
    if parts:
        return "/".join(f"{{{p}}}" for p in parts)
    return f"projects/{{project}}/{resource_type}/{{name}}"


def _infer_alicloud_pattern(service: str, resource_type: str, stub: dict) -> str:
    """Build AliCloud ARN from stub or template."""
    pattern = stub.get("pattern", "")
    if pattern:
        return pattern
    resource_id_param = stub.get("resource_identifiers", f"{_snake_to_pascal(resource_type)}Id")
    rt_seg = resource_type.upper()
    return f"acs:{service}:${{Region}}:${{AccountId}}:{rt_seg}/${{{resource_id_param}}}"


def _infer_ibm_pattern(service: str, resource_type: str, stub: dict) -> str:
    """Build IBM CRN from stub or template."""
    pattern = stub.get("pattern", "")
    if pattern:
        return pattern
    return (
        f"crn:v1:bluemix:public:{service}:${{Region}}:"
        f"a/${{AccountId}}:::{resource_type}:${{ResourceId}}"
    )


def _infer_oci_pattern(service: str, resource_type: str, stub: dict) -> str:
    """Build OCI OCID from stub or template."""
    pattern = stub.get("pattern", "")
    if pattern:
        return pattern
    rt_seg = resource_type.replace("_", ".")
    return f"ocid1.{rt_seg}.oc1.${{Realm}}.${{UniqueId}}"


# ── Loaders ────────────────────────────────────────────────────────────────────

def _load_stub(svc_dir: Path, filename: str) -> dict:
    """Load a single-resource identifier stub file if it exists."""
    p = svc_dir / filename
    return json.loads(p.read_text()) if p.exists() else {}


def _load_arn_mapping(svc_dir: Path) -> dict:
    """Load resource_arn_mapping.json → analysis.resources dict."""
    p = svc_dir / "resource_arn_mapping.json"
    if not p.exists():
        return {}
    raw = json.loads(p.read_text())
    return raw.get("analysis", {}).get("resources", {})


# ── Main enrichment ────────────────────────────────────────────────────────────

def enrich_step5(svc_dir: Path, csp: str) -> bool:
    step5_path = svc_dir / "step5_resource_catalog_inventory_enrich.json"
    if not step5_path.exists():
        return False

    data = json.loads(step5_path.read_text())
    resources = data.get("resources", {})
    if not resources:
        return False

    service = data.get("service", svc_dir.name)
    modified = False

    # Load identifier stubs (used as fallback / override)
    aws_stub    = _load_stub(svc_dir, "resource_arn_mapping.json")  # handled separately
    ali_stub    = _load_stub(svc_dir, "arn_identifier.json")
    ibm_stub    = _load_stub(svc_dir, "crn_identifier.json")
    oci_stub    = _load_stub(svc_dir, "ocid_identifier.json")
    arn_mapping = _load_arn_mapping(svc_dir)

    for rtype, res in resources.items():
        identifier = res.get("identifier", {})

        # Skip if already has a real pattern
        existing = res.get("identifier_pattern", "")
        if existing and "${" in existing:
            continue

        if csp == "aws":
            pattern = _infer_aws_pattern(service, rtype, identifier)
        elif csp == "gcp":
            pattern = _infer_gcp_pattern(service, rtype, identifier)
        elif csp == "alicloud":
            pattern = _infer_alicloud_pattern(service, rtype, ali_stub)
        elif csp == "ibm":
            pattern = _infer_ibm_pattern(service, rtype, ibm_stub)
        elif csp == "oci":
            pattern = _infer_oci_pattern(service, rtype, oci_stub)
        else:
            continue

        if pattern:
            res["identifier_pattern"] = pattern
            modified = True

    if modified:
        step5_path.write_text(json.dumps(data, indent=2))
    return modified


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp", default="all",
                        help="aws|gcp|azure|alicloud|ibm|oci|all")
    args = parser.parse_args()

    CSP_DIRS = {
        "aws":      BASE / "aws",
        "gcp":      BASE / "gcp",
        "azure":    BASE / "azure",
        "alicloud": BASE / "alicloud",
        "ibm":      BASE / "ibm",
        "oci":      BASE / "oci",
    }

    targets = list(CSP_DIRS.keys()) if args.csp == "all" else [args.csp]

    for csp in targets:
        csp_dir = CSP_DIRS.get(csp)
        if not csp_dir or not csp_dir.exists():
            print(f"[{csp}] directory not found, skipping")
            continue

        skip = {"temp_code", "tools", "__pycache__"}
        svc_dirs = sorted(d for d in csp_dir.iterdir()
                          if d.is_dir() and d.name not in skip)

        updated = 0
        skipped = 0
        for svc_dir in svc_dirs:
            if enrich_step5(svc_dir, csp):
                updated += 1
            else:
                skipped += 1

        print(f"[{csp}] {updated} services enriched, {skipped} skipped/unchanged")


if __name__ == "__main__":
    main()
