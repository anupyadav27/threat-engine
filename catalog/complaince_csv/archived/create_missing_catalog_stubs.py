#!/usr/bin/env python3
"""
create_missing_catalog_stubs.py
================================
Creates minimal metadata YAML stubs in catalog/rule/{csp}_rule_metadata/
for every rule_id that appears in the compliance CSV but has no catalog file.

These stubs allow the compliance mapping pipeline to link rule_ids to
compliance controls. The actual check logic can be added later.

Usage:
    python create_missing_catalog_stubs.py          # dry-run (print only)
    python create_missing_catalog_stubs.py --write  # actually create files
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, Set

ROOT    = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "rule"
MISSING = Path(__file__).parent / "missing_catalog_rules.txt"

# CSP → documentation base URL
CSP_DOC_URLS = {
    "aws":      "https://docs.aws.amazon.com/",
    "azure":    "https://learn.microsoft.com/en-us/azure/",
    "gcp":      "https://cloud.google.com/docs/",
    "oci":      "https://docs.oracle.com/en-us/iaas/",
    "ibm":      "https://cloud.ibm.com/docs/",
    "alicloud": "https://www.alibabacloud.com/help/",
    "k8s":      "https://kubernetes.io/docs/",
}

CSP_NAMES = {
    "aws": "AWS", "azure": "Azure", "gcp": "GCP",
    "oci": "OCI", "ibm": "IBM", "alicloud": "AliCloud", "k8s": "Kubernetes",
}

# Infer domain from service/resource tokens
def infer_domain(parts: list[str]) -> str:
    tokens = set(p.lower() for p in parts)
    if any(t in tokens for t in ["iam", "ram", "rbac", "identity", "auth", "role", "policy", "mfa", "access"]):
        return "identity_and_access_management"
    if any(t in tokens for t in ["logging", "log", "audit", "trail", "monitor", "activity"]):
        return "logging_and_monitoring"
    if any(t in tokens for t in ["network", "vpc", "firewall", "secgroup", "networkpolicy", "nsg"]):
        return "network_security"
    if any(t in tokens for t in ["kms", "encryption", "crypto", "key", "secret"]):
        return "data_protection_and_privacy"
    if any(t in tokens for t in ["k8s", "container", "pod", "cluster", "kubectl", "kubelet", "etcd"]):
        return "container_and_kubernetes_security"
    if any(t in tokens for t in ["s3", "storage", "blob", "bucket", "oss", "cos"]):
        return "data_protection_and_privacy"
    if any(t in tokens for t in ["chain", "attack", "threat", "ciem", "anomaly", "exfil"]):
        return "threat_detection_and_response"
    return "configuration_and_change_management"


def infer_severity(parts: list[str]) -> str:
    tokens = set(p.lower() for p in parts)
    if any(t in tokens for t in ["critical", "root", "admin", "privilege", "escalation", "chain"]):
        return "critical"
    if any(t in tokens for t in ["high", "public", "exposed", "anonymous", "bypass", "disable"]):
        return "high"
    return "medium"


def rule_id_to_title(rule_id: str, csp: str) -> str:
    """Convert rule_id like 'gcp.logging.sink.destination_and_filter' to a readable title."""
    parts = rule_id.split(".")
    # Skip CSP prefix
    rest = parts[1:] if len(parts) > 1 else parts
    # Convert underscores → spaces, capitalize each word
    words = []
    for part in rest:
        words.extend(part.replace("_", " ").split())
    return f"{CSP_NAMES.get(csp, csp.upper())} {' '.join(w.capitalize() for w in words)}"


def make_stub_yaml(rule_id: str) -> str:
    parts = rule_id.split(".")
    csp = parts[0].lower() if parts else "unknown"
    service = parts[1] if len(parts) > 1 else "general"
    resource = parts[2] if len(parts) > 2 else "resource"
    requirement_parts = parts[3:] if len(parts) > 3 else [parts[-1]]
    requirement = " ".join(p.replace("_", " ").capitalize() for p in requirement_parts)

    csp_name = CSP_NAMES.get(csp, csp.upper())
    title = rule_id_to_title(rule_id, csp)
    domain = infer_domain(parts)
    severity = infer_severity(parts)
    doc_url = CSP_DOC_URLS.get(csp, "https://docs.example.com/")

    # Determine subcategory
    subcategory_map = {
        "identity_and_access_management": "access_control",
        "logging_and_monitoring": "logging",
        "network_security": "network_configuration",
        "data_protection_and_privacy": "encryption",
        "container_and_kubernetes_security": "container_security",
        "threat_detection_and_response": "threat_detection",
        "configuration_and_change_management": "configuration",
    }
    subcategory = subcategory_map.get(domain, "configuration")

    return f"""rule_id: {rule_id}
title: '{title}'
scope: {service}.{resource}
domain: {domain}
subcategory: {subcategory}
severity: {severity}
service: {service}
resource: {resource}
requirement: {requirement}
description: >-
  Validates that {csp_name} {service} {resource} has {requirement.lower()}
  configured according to security best practices. Proper configuration
  reduces security risks and ensures compliance with regulatory standards.
rationale: >-
  Ensures {csp_name} {service} {resource} has {requirement.lower()} properly
  configured for security compliance and regulatory alignment.
remediation: >-
  Review and configure {requirement.lower()} for {csp_name} {service} {resource}
  according to security best practices. Refer to the {csp_name} documentation.
references:
- {doc_url}
compliance: []
source: compliance_stub
metadata_source: compliance_mapping
generated_by: create_missing_catalog_stubs
"""


def load_missing_rule_ids() -> Dict[str, Set[str]]:
    """Parse missing_catalog_rules.txt → {csp: {rule_id, ...}}"""
    result: Dict[str, Set[str]] = {}
    with open(MISSING) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: "rule_id  (CSP=csp, refs=N)"
            rid = line.split("(")[0].strip()
            if not rid or not "." in rid:
                continue
            csp = rid.split(".")[0].lower()
            if csp not in result:
                result[csp] = set()
            result[csp].add(rid)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Actually create files (default: dry-run)")
    args = parser.parse_args()

    if not MISSING.exists():
        print(f"Missing report not found: {MISSING}")
        print("Run fix_csv_rule_ids.py first to generate it.")
        return

    missing = load_missing_rule_ids()
    total = sum(len(v) for v in missing.values())
    print(f"Found {total} missing rule_ids across {len(missing)} CSPs:")
    for csp, rules in sorted(missing.items()):
        print(f"  {csp}: {len(rules)}")

    if not args.write:
        print("\n[DRY-RUN] No files written. Pass --write to create stubs.")
        print("\nExample stub that would be created:")
        sample = next(iter(next(iter(missing.values()))))
        print(make_stub_yaml(sample))
        return

    created = 0
    skipped = 0
    for csp, rule_ids in sorted(missing.items()):
        meta_dir = CATALOG / f"{csp}_rule_metadata"
        if not meta_dir.exists():
            print(f"  [{csp}] metadata dir not found — skipping")
            continue

        for rule_id in sorted(rule_ids):
            # Skip garbage rows
            if "." not in rule_id or len(rule_id.split(".")) < 2:
                continue

            # Determine subdirectory from service (parts[1])
            parts = rule_id.split(".")
            service = parts[1]
            service_dir = meta_dir / service
            service_dir.mkdir(exist_ok=True)

            out_path = service_dir / f"{rule_id}.yaml"
            if out_path.exists():
                skipped += 1
                continue

            yaml_content = make_stub_yaml(rule_id)
            out_path.write_text(yaml_content, encoding="utf-8")
            created += 1

    print(f"\nCreated {created} stub YAML files, skipped {skipped} (already exist)")
    print("\nNext step: re-run fix_csv_rule_ids.py to verify 0 unmatched entries")


if __name__ == "__main__":
    main()
