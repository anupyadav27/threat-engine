#!/usr/bin/env python3
"""
Add orphan rules to the Azure catalog YAML.

Orphan rules are rules that exist in check/metadata files but are missing
from the azure_rules_by_category.yaml catalog.

This script:
1. Loads the catalog YAML (without resolving anchors/aliases)
2. Extracts all existing rule_ids
3. Scans metadata directories for orphan rules
4. Adds orphans to the correct service/resource section
5. Writes the updated catalog
"""

import os
import sys
import re
import yaml
from collections import defaultdict
from pathlib import Path

# Paths
CATALOG_PATH = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rules_by_category.yaml"
METADATA_DIR = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rule_metadata"

# Services to check for orphans
TARGET_SERVICES = [
    "azure_arc",
    "backup",
    "communication",
    "compute",
    "data_factory",
    "general",
    "key_vault",
    "lighthouse",
    "monitoring",
    "network",
    "security_center_-_granular_pricing",
    "sql",
    "storage",
    "tags",
]

# Expected orphan counts per service
EXPECTED_ORPHAN_COUNTS = {
    "azure_arc": 2,
    "backup": 6,
    "communication": 1,
    "compute": 4,
    "data_factory": 1,
    "general": 1,
    "key_vault": 1,
    "lighthouse": 1,
    "monitoring": 1,
    "network": 2,
    "security_center_-_granular_pricing": 2,
    "sql": 1,
    "storage": 1,
    "tags": 5,
}

# Domain -> compliance frameworks mapping (inferred from catalog patterns)
DOMAIN_COMPLIANCE_MAP = {
    "identity_and_access_management": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "CMMC_L2_v1.9.0",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "configuration_and_change_management": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "data_protection": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "CMMC_L2_v1.9.0",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "network_security": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "CMMC_L2_v1.9.0",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "logging_monitoring_and_alerting": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "CMMC_L2_v1.9.0",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "compliance_and_governance": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "resilience_and_disaster_recovery": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
    "security_operations": [
        "CIS_Controls_v8.1",
        "CMMC_2_0_L2",
        "EU_GDPR_2016_679",
        "FedRAMP_H_audit",
        "FedRAMP_M_audit",
        "HIPAA_HITRUST_audit",
        "ISO27001_2013_audit",
        "K_ISMS_P_2023",
        "NIS2",
        "NIST_SP_800-171_R2",
        "NIST_SP_800-53_R4",
        "NIST_SP_800-53_R5",
        "NL_BIO_Cloud_Theme_V2",
        "PCI_DSS_V4.0",
        "SOC_2",
        "Spain_ENS",
    ],
}


def extract_catalog_rule_ids(catalog_path):
    """Extract all rule_ids from the catalog YAML file."""
    rule_ids = set()
    with open(catalog_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("rule_id:"):
                rule_id = line.split("rule_id:", 1)[1].strip()
                rule_ids.add(rule_id)
    return rule_ids


def get_metadata_rules(metadata_dir, service):
    """Get all metadata rule files for a service."""
    service_dir = os.path.join(metadata_dir, service)
    if not os.path.isdir(service_dir):
        print(f"  WARNING: Service directory not found: {service_dir}")
        return []

    rules = []
    for fname in sorted(os.listdir(service_dir)):
        if fname.endswith(".yaml"):
            fpath = os.path.join(service_dir, fname)
            try:
                with open(fpath, "r") as f:
                    meta = yaml.safe_load(f)
                if meta and "rule_id" in meta:
                    rules.append(meta)
            except Exception as e:
                print(f"  ERROR reading {fpath}: {e}")
    return rules


def find_orphan_rules(catalog_rule_ids, metadata_dir, services):
    """Find rules in metadata that are missing from the catalog."""
    orphans = defaultdict(list)
    for service in services:
        meta_rules = get_metadata_rules(metadata_dir, service)
        for rule in meta_rules:
            rule_id = rule["rule_id"]
            if rule_id not in catalog_rule_ids:
                orphans[service].append(rule)
    return orphans


def get_domain_compliance_from_catalog(catalog_lines, domain):
    """
    Scan the catalog for existing rules with the same domain to extract
    their compliance frameworks. Returns the list of frameworks.
    """
    # We already have a static map built from catalog analysis
    if domain in DOMAIN_COMPLIANCE_MAP:
        return DOMAIN_COMPLIANCE_MAP[domain]
    # Fallback: use configuration_and_change_management frameworks
    return DOMAIN_COMPLIANCE_MAP.get("configuration_and_change_management", [])


def build_rule_entry(rule_meta, domain_compliance):
    """
    Build a catalog entry dict from metadata.
    """
    entry = {}

    # assertion_id: from metadata if present, otherwise derive from service.check_name
    if "assertion_id" in rule_meta and rule_meta["assertion_id"]:
        entry["assertion_id"] = rule_meta["assertion_id"]
    else:
        # Derive: service.check_name_part
        service = rule_meta.get("service", "")
        rule_id = rule_meta.get("rule_id", "")
        # rule_id format: azure.service.resource.check_name
        parts = rule_id.split(".")
        if len(parts) >= 4:
            check_name = parts[3]
            entry["assertion_id"] = f"{service}.{check_name}"
        else:
            entry["assertion_id"] = rule_id

    entry["domain"] = rule_meta.get("domain", "configuration_and_change_management")

    # Include policy_id if present
    if "policy_id" in rule_meta and rule_meta["policy_id"]:
        entry["policy_id"] = rule_meta["policy_id"]

    # Include program if present
    if "program" in rule_meta and rule_meta["program"]:
        entry["program"] = rule_meta["program"]

    # Include provider_category if present
    if "provider_category" in rule_meta and rule_meta["provider_category"]:
        entry["provider_category"] = rule_meta["provider_category"]

    # Include resource_class if present
    if "resource_class" in rule_meta and rule_meta["resource_class"]:
        entry["resource_class"] = rule_meta["resource_class"]

    entry["rule_id"] = rule_meta["rule_id"]
    entry["scope"] = rule_meta.get("scope", f"{rule_meta.get('service', '')}.{rule_meta.get('resource', '')}")
    entry["severity"] = rule_meta.get("severity", "medium")
    entry["source"] = rule_meta.get("source", "azure_policy_builtin")

    # Compliance: use metadata compliance if present, otherwise infer from domain
    if "compliance" in rule_meta and rule_meta["compliance"]:
        entry["compliance"] = rule_meta["compliance"]
        # No compliance_source needed since it came from the metadata
    else:
        entry["compliance"] = domain_compliance
        entry["compliance_source"] = "domain_inference"

    return entry


def format_rule_yaml(entry, indent=2):
    """Format a single rule entry as YAML text with proper indentation."""
    lines = []
    prefix = " " * indent

    # Write fields in a consistent order matching the catalog
    field_order = [
        "assertion_id", "domain", "policy_id", "program",
        "provider_category", "resource_class",
        "rule_id", "scope", "severity", "source",
        "compliance", "compliance_source",
    ]

    first = True
    for field in field_order:
        if field not in entry:
            continue
        value = entry[field]
        if field == "compliance" and isinstance(value, list):
            if first:
                lines.append(f"{prefix}- {field}:")
                first = False
            else:
                lines.append(f"{prefix}  {field}:")
            for fw in value:
                lines.append(f"{prefix}  - {fw}")
        else:
            if first:
                lines.append(f"{prefix}- {field}: {value}")
                first = False
            else:
                lines.append(f"{prefix}  {field}: {value}")

    return "\n".join(lines)


def find_insert_position(lines, service, resource):
    """
    Find the line position to insert a new rule into an existing
    service/resource section in the catalog.

    Returns (line_index, indent_level) where:
    - line_index is the line number to insert BEFORE
    - indent_level is the indentation level for the rule entry
    """
    in_service = False
    in_resource = False
    last_rule_end = -1
    service_start = -1
    service_indent = 0

    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Detect top-level service (no indentation)
        leading = len(line) - len(line.lstrip())

        if leading == 0 and stripped.endswith(":"):
            svc_name = stripped[:-1]
            if svc_name == service:
                in_service = True
                service_start = i
                service_indent = 0
                continue
            elif in_service:
                # Hit next service, insert before this
                if last_rule_end > 0:
                    return last_rule_end, 2
                break

        if in_service:
            # Resource level (2 spaces indent)
            if leading == 2 and stripped.endswith(":"):
                res_name = stripped.strip().rstrip(":")
                if res_name == resource:
                    in_resource = True
                    continue
                elif in_resource:
                    # Hit next resource, insert before this
                    if last_rule_end > 0:
                        return last_rule_end, 2
                    break

            if in_resource:
                # Track the last line of rule entries
                last_rule_end = i + 1

    if in_resource and last_rule_end > 0:
        return last_rule_end, 2

    return -1, 2


def find_service_end(lines, service):
    """Find the line after the last line of a service section."""
    in_service = False
    last_line = -1

    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if not stripped:
            if in_service:
                last_line = i
            continue

        leading = len(line) - len(line.lstrip())

        if leading == 0 and stripped.endswith(":"):
            svc_name = stripped[:-1]
            if svc_name == service:
                in_service = True
                last_line = i + 1
                continue
            elif in_service:
                return i  # Insert before next service

        if in_service:
            last_line = i + 1

    if in_service and last_line > 0:
        return last_line

    return -1


def find_resource_end(lines, service, resource):
    """Find the end position of a specific resource within a service."""
    in_service = False
    in_resource = False
    last_line = -1

    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if not stripped:
            if in_resource:
                last_line = i
            continue
        if stripped.startswith("#"):
            continue

        leading = len(line) - len(line.lstrip())

        if leading == 0 and stripped.endswith(":"):
            svc_name = stripped[:-1]
            if svc_name == service:
                in_service = True
                continue
            elif in_service:
                if in_resource:
                    return last_line if last_line > 0 else i
                return -1

        if in_service:
            if leading == 2 and stripped.endswith(":"):
                res_name = stripped.strip().rstrip(":")
                if res_name == resource:
                    in_resource = True
                    last_line = i + 1
                    continue
                elif in_resource:
                    return last_line if last_line > 0 else i

            if in_resource:
                last_line = i + 1

    if in_resource and last_line > 0:
        return last_line
    return -1


def add_rules_to_catalog(catalog_path, orphans):
    """
    Add orphan rules to the catalog YAML file.
    Uses line-by-line manipulation to preserve YAML anchors/aliases.
    """
    with open(catalog_path, "r") as f:
        lines = f.readlines()

    # Track insertions (will apply from bottom to top to preserve line numbers)
    insertions = []  # List of (line_index, text_to_insert)
    new_sections = []  # List of text blocks for new services

    for service, rules in sorted(orphans.items()):
        # Group rules by resource
        rules_by_resource = defaultdict(list)
        for rule in rules:
            resource = rule.get("resource", "unknown")
            rules_by_resource[resource].append(rule)

        # Check if service exists in catalog
        service_exists = False
        for line in lines:
            stripped = line.strip()
            if stripped == f"{service}:" and len(line) - len(line.lstrip()) == 0:
                service_exists = True
                break

        if service_exists:
            for resource, res_rules in sorted(rules_by_resource.items()):
                # Check if resource exists in service
                resource_exists = False
                in_service = False
                for line in lines:
                    stripped = line.strip()
                    leading = len(line) - len(line.lstrip())
                    if leading == 0 and stripped == f"{service}:":
                        in_service = True
                        continue
                    elif leading == 0 and stripped.endswith(":") and in_service:
                        break
                    if in_service and leading == 2 and stripped == f"{resource}:":
                        resource_exists = True
                        break

                if resource_exists:
                    # Find end of resource section and insert there
                    insert_pos = find_resource_end(lines, service, resource)
                    if insert_pos > 0:
                        # Get domain compliance
                        domain = res_rules[0].get("domain", "configuration_and_change_management")
                        domain_compliance = get_domain_compliance_from_catalog(lines, domain)

                        rule_texts = []
                        for rule in res_rules:
                            entry = build_rule_entry(rule, domain_compliance)
                            rule_text = format_rule_yaml(entry, indent=2)
                            rule_texts.append(rule_text)

                        insert_text = "\n".join(rule_texts) + "\n"
                        insertions.append((insert_pos, insert_text))
                    else:
                        print(f"  WARNING: Could not find end of {service}.{resource}")
                else:
                    # Add new resource section to service
                    svc_end = find_service_end(lines, service)
                    if svc_end > 0:
                        domain = res_rules[0].get("domain", "configuration_and_change_management")
                        domain_compliance = get_domain_compliance_from_catalog(lines, domain)

                        resource_block = f"  {resource}:\n"
                        for rule in res_rules:
                            entry = build_rule_entry(rule, domain_compliance)
                            rule_text = format_rule_yaml(entry, indent=2)
                            resource_block += rule_text + "\n"

                        insertions.append((svc_end, resource_block))
                    else:
                        print(f"  WARNING: Could not find end of service {service}")
        else:
            # Create entirely new service section
            section_text = f"{service}:\n"
            for resource, res_rules in sorted(rules_by_resource.items()):
                domain = res_rules[0].get("domain", "configuration_and_change_management")
                domain_compliance = get_domain_compliance_from_catalog(lines, domain)

                section_text += f"  {resource}:\n"
                for rule in res_rules:
                    entry = build_rule_entry(rule, domain_compliance)
                    rule_text = format_rule_yaml(entry, indent=2)
                    section_text += rule_text + "\n"

            new_sections.append(section_text)

    # Apply insertions from bottom to top to preserve line numbers
    insertions.sort(key=lambda x: x[0], reverse=True)
    for pos, text in insertions:
        insert_lines = text.split("\n")
        # Remove trailing empty string from split
        if insert_lines and insert_lines[-1] == "":
            insert_lines = insert_lines[:-1]
        for j, insert_line in enumerate(reversed(insert_lines)):
            lines.insert(pos, insert_line + "\n")

    # Append new sections at the end
    for section in new_sections:
        lines.append(section)

    # Write back
    with open(catalog_path, "w") as f:
        f.writelines(lines)

    return len(insertions) + len(new_sections)


def main():
    print("=" * 70)
    print("ADD ORPHAN RULES TO AZURE CATALOG")
    print("=" * 70)

    # Step 1: Extract existing rule_ids from catalog
    print("\n[1] Extracting existing rule_ids from catalog...")
    catalog_rule_ids = extract_catalog_rule_ids(CATALOG_PATH)
    print(f"    Found {len(catalog_rule_ids)} rules in catalog")

    # Step 2: Find orphan rules
    print("\n[2] Scanning metadata directories for orphan rules...")
    orphans = find_orphan_rules(catalog_rule_ids, METADATA_DIR, TARGET_SERVICES)

    total_orphans = sum(len(rules) for rules in orphans.values())
    print(f"\n    Total orphan rules found: {total_orphans}")
    print(f"    Expected: 29")

    print("\n    Orphans by service:")
    for service in sorted(orphans.keys()):
        count = len(orphans[service])
        expected = EXPECTED_ORPHAN_COUNTS.get(service, "?")
        status = "OK" if count == expected else f"MISMATCH (expected {expected})"
        print(f"      {service}: {count} [{status}]")
        for rule in orphans[service]:
            print(f"        - {rule['rule_id']}")

    if total_orphans != 29:
        print(f"\n    WARNING: Found {total_orphans} orphans, expected 29")
        print("    Proceeding anyway...")

    # Step 3: Add orphan rules to catalog
    print(f"\n[3] Adding {total_orphans} orphan rules to catalog...")
    ops = add_rules_to_catalog(CATALOG_PATH, orphans)
    print(f"    Performed {ops} insertion operations")

    # Step 4: Verify
    print("\n[4] Verifying...")
    new_catalog_rule_ids = extract_catalog_rule_ids(CATALOG_PATH)
    print(f"    Rules in catalog before: {len(catalog_rule_ids)}")
    print(f"    Rules in catalog after:  {len(new_catalog_rule_ids)}")
    print(f"    Rules added:             {len(new_catalog_rule_ids) - len(catalog_rule_ids)}")

    # Check all orphans are now in catalog
    missing = []
    for service, rules in orphans.items():
        for rule in rules:
            if rule["rule_id"] not in new_catalog_rule_ids:
                missing.append(rule["rule_id"])

    if missing:
        print(f"\n    ERROR: {len(missing)} orphan rules still missing from catalog:")
        for rule_id in missing:
            print(f"      - {rule_id}")
        return 1
    else:
        print(f"\n    SUCCESS: All {total_orphans} orphan rules added to catalog")

    # Step 5: Validate YAML
    print("\n[5] Validating output YAML...")
    try:
        with open(CATALOG_PATH, "r") as f:
            data = yaml.safe_load(f)
        print(f"    YAML is valid. Top-level keys: {len(data)}")
    except yaml.YAMLError as e:
        print(f"    ERROR: YAML validation failed: {e}")
        return 1

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
