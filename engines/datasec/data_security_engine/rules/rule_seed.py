"""
DataSec Rule Seed Script

Reads config/rule_module_mapping.yaml and populates the datasec_rules table
with rule definitions for AWS (from YAML) plus stub rules for Azure, GCP, K8s, OCI.

Usage:
    python -m data_security_engine.rules.rule_seed
    python -m data_security_engine.rules.rule_seed --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import psycopg2
from psycopg2.extras import Json
import yaml


# ── Severity mapping by category ─────────────────────────────────────────
CATEGORY_SEVERITY: Dict[str, str] = {
    "data_protection_encryption": "high",
    "data_access_governance": "high",
    "data_classification": "critical",
    "data_residency": "medium",
    "data_compliance": "medium",
    "data_activity_monitoring": "medium",
    "data_lineage": "low",
}

# ── Compliance frameworks by category ─────────────────────────────────────
CATEGORY_COMPLIANCE: Dict[str, List[str]] = {
    "data_protection_encryption": [
        "PCI-DSS", "NIST-800-53", "ISO-27001", "SOC-2", "HIPAA",
    ],
    "data_access_governance": [
        "CIS", "NIST-800-53", "ISO-27001", "SOC-2",
    ],
    "data_classification": [
        "GDPR", "HIPAA", "PCI-DSS", "NIST-800-53",
    ],
    "data_residency": [
        "GDPR", "ISO-27001",
    ],
    "data_compliance": [
        "NIST-800-53", "ISO-27001", "SOC-2", "HIPAA",
    ],
    "data_activity_monitoring": [
        "CIS", "NIST-800-53", "SOC-2",
    ],
    "data_lineage": [
        "NIST-800-53",
    ],
}

# ── Condition templates by category ───────────────────────────────────────
CATEGORY_CONDITION: Dict[str, Dict[str, Any]] = {
    "data_protection_encryption": {
        "type": "field_check",
        "field": "finding_data.encryption_enabled",
        "operator": "equals",
        "expected": True,
    },
    "data_access_governance": {
        "type": "field_check",
        "field": "finding_data.public_access_blocked",
        "operator": "equals",
        "expected": True,
    },
    "data_activity_monitoring": {
        "type": "field_check",
        "field": "finding_data.logging_enabled",
        "operator": "equals",
        "expected": True,
    },
    "data_residency": {
        "type": "field_check",
        "field": "finding_data.replication_configured",
        "operator": "equals",
        "expected": True,
    },
    "data_compliance": {
        "type": "field_check",
        "field": "finding_data.retention_configured",
        "operator": "equals",
        "expected": True,
    },
    "data_classification": {
        "type": "field_check",
        "field": "finding_data.classification_enabled",
        "operator": "equals",
        "expected": True,
    },
}

# ── Multi-CSP stub prefixes ──────────────────────────────────────────────
MULTI_CSP_MAP: Dict[str, str] = {
    "azure": "azure",
    "gcp": "gcp",
    "k8s": "k8s",
    "oci": "oci",
}

# ── Service to resource_type best-effort mapping ─────────────────────────
SERVICE_RESOURCE_TYPE: Dict[str, str] = {
    "s3": "bucket",
    "rds": "db_instance",
    "dynamodb": "table",
    "redshift": "cluster",
    "kms": "key",
    "cloudtrail": "trail",
}

# ── Domain mapping (category prefix) ─────────────────────────────────────
CATEGORY_DOMAIN: Dict[str, str] = {
    "data_protection_encryption": "encryption",
    "data_access_governance": "access",
    "data_activity_monitoring": "monitoring",
    "data_residency": "residency",
    "data_compliance": "compliance",
    "data_classification": "classification",
}


def _get_db_connection():
    """Create a psycopg2 connection to the datasec database."""
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DATASEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DATASEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def _title_from_rule_id(rule_id: str) -> str:
    """Generate a human-readable title from a dotted rule_id.

    Example:
        aws.s3.bucket.encryption_at_rest_enabled
        -> S3 Bucket Encryption At Rest Enabled
    """
    parts = rule_id.split(".")
    # Drop the CSP prefix (first part)
    meaningful = parts[1:]
    words = " ".join(meaningful).replace("_", " ").title()
    return words


def _load_yaml(yaml_path: Path) -> Dict[str, Any]:
    """Load and return the rule_module_mapping.yaml."""
    with open(yaml_path, "r") as f:
        return yaml.safe_load(f)


def _collect_aws_rules(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse YAML and return a flat list of rule dicts for AWS."""
    rules: List[Dict[str, Any]] = []

    # Process services section
    services = data.get("services", {})
    for service_key, categories in services.items():
        for category_key, cat_block in categories.items():
            if not isinstance(cat_block, dict):
                continue
            rule_ids = cat_block.get("rules", [])
            for rule_id in rule_ids:
                rules.append(_make_rule(
                    rule_id=rule_id,
                    csp="aws",
                    service=service_key,
                    category=category_key,
                ))

    # Process cross_service section
    cross_service = data.get("cross_service", {})
    for service_key, categories in cross_service.items():
        for category_key, cat_block in categories.items():
            if not isinstance(cat_block, dict):
                continue
            rule_ids = cat_block.get("rules", [])
            for rule_id in rule_ids:
                rules.append(_make_rule(
                    rule_id=rule_id,
                    csp="aws",
                    service=service_key,
                    category=category_key,
                ))

    return rules


def _make_rule(
    rule_id: str,
    csp: str,
    service: str,
    category: str,
) -> Dict[str, Any]:
    """Build a single rule dict ready for DB insertion."""
    severity = CATEGORY_SEVERITY.get(category, "medium")
    compliance = CATEGORY_COMPLIANCE.get(category, [])
    condition = CATEGORY_CONDITION.get(category, {"type": "field_check"})
    resource_type = SERVICE_RESOURCE_TYPE.get(service)
    domain = CATEGORY_DOMAIN.get(category, "general")

    return {
        "rule_id": rule_id,
        "csp": csp,
        "service": service,
        "resource_type": resource_type,
        "category": category,
        "severity": severity,
        "title": _title_from_rule_id(rule_id),
        "description": f"Data security check: {_title_from_rule_id(rule_id)}",
        "condition": condition,
        "condition_type": "field_check",
        "compliance_frameworks": compliance,
        "domain": domain,
        "check_rule_id": rule_id,
        "is_active": True,
        "version": "1.0",
    }


def _generate_multi_csp_stubs(aws_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate equivalent stub rules for Azure, GCP, K8s, and OCI.

    Replaces the 'aws.' prefix with the target CSP prefix and adjusts
    the csp field accordingly.
    """
    stubs: List[Dict[str, Any]] = []
    for csp_key, csp_prefix in MULTI_CSP_MAP.items():
        for aws_rule in aws_rules:
            original_id = aws_rule["rule_id"]
            if not original_id.startswith("aws."):
                continue
            new_rule_id = csp_prefix + original_id[3:]  # replace 'aws' prefix
            stub = {
                **aws_rule,
                "rule_id": new_rule_id,
                "csp": csp_key,
                "check_rule_id": new_rule_id,
                "title": _title_from_rule_id(new_rule_id),
                "description": f"Data security check: {_title_from_rule_id(new_rule_id)}",
                "is_active": False,  # stubs start inactive
            }
            stubs.append(stub)
    return stubs


INSERT_SQL = """
    INSERT INTO datasec_rules (
        rule_id, csp, service, resource_type, category,
        severity, title, description, condition, condition_type,
        compliance_frameworks, sensitive_data_types, domain,
        check_rule_id, tenant_id, is_active, version
    ) VALUES (
        %(rule_id)s, %(csp)s, %(service)s, %(resource_type)s, %(category)s,
        %(severity)s, %(title)s, %(description)s,
        %(condition)s, %(condition_type)s,
        %(compliance_frameworks)s, %(sensitive_data_types)s, %(domain)s,
        %(check_rule_id)s, %(tenant_id)s, %(is_active)s, %(version)s
    )
    ON CONFLICT (rule_id, csp, tenant_id)
    DO UPDATE SET
        service     = EXCLUDED.service,
        category    = EXCLUDED.category,
        severity    = EXCLUDED.severity,
        title       = EXCLUDED.title,
        description = EXCLUDED.description,
        condition   = EXCLUDED.condition,
        compliance_frameworks = EXCLUDED.compliance_frameworks,
        domain      = EXCLUDED.domain,
        check_rule_id = EXCLUDED.check_rule_id,
        is_active   = EXCLUDED.is_active,
        version     = EXCLUDED.version,
        updated_at  = NOW()
"""


def _insert_rules(
    conn,
    rules: List[Dict[str, Any]],
    dry_run: bool = False,
) -> int:
    """Insert rules into datasec_rules. Returns count of rows upserted."""
    count = 0
    with conn.cursor() as cur:
        for rule in rules:
            params = {
                "rule_id": rule["rule_id"],
                "csp": rule["csp"],
                "service": rule["service"],
                "resource_type": rule.get("resource_type"),
                "category": rule["category"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule.get("description"),
                "condition": Json(rule.get("condition", {})),
                "condition_type": rule.get("condition_type", "field_check"),
                "compliance_frameworks": Json(rule.get("compliance_frameworks", [])),
                "sensitive_data_types": Json(rule.get("sensitive_data_types", [])),
                "domain": rule.get("domain"),
                "check_rule_id": rule.get("check_rule_id"),
                "tenant_id": None,  # global rules have NULL tenant_id
                "is_active": rule.get("is_active", True),
                "version": rule.get("version", "1.0"),
            }
            if dry_run:
                print(f"  [DRY-RUN] {rule['csp']:5s} | {rule['rule_id']}")
            else:
                cur.execute(INSERT_SQL, params)
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Seed datasec_rules from YAML")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print rules without inserting into DB",
    )
    parser.add_argument(
        "--yaml-path",
        type=str,
        default=None,
        help="Path to rule_module_mapping.yaml (auto-detected if omitted)",
    )
    args = parser.parse_args()

    # Resolve YAML path
    if args.yaml_path:
        yaml_path = Path(args.yaml_path)
    else:
        # Try relative to this file first, then common project locations
        candidates = [
            Path(__file__).resolve().parent.parent.parent / "config" / "rule_module_mapping.yaml",
            Path(__file__).resolve().parent.parent / "config" / "rule_module_mapping.yaml",
        ]
        yaml_path = None
        for candidate in candidates:
            if candidate.exists():
                yaml_path = candidate
                break
        if yaml_path is None:
            print("ERROR: Could not locate rule_module_mapping.yaml")
            print("Searched:", [str(c) for c in candidates])
            sys.exit(1)

    print(f"Loading YAML: {yaml_path}")
    data = _load_yaml(yaml_path)

    # Collect AWS rules from YAML
    aws_rules = _collect_aws_rules(data)
    print(f"  AWS rules from YAML: {len(aws_rules)}")

    # Generate multi-CSP stubs
    multi_csp_stubs = _generate_multi_csp_stubs(aws_rules)
    print(f"  Multi-CSP stubs:     {len(multi_csp_stubs)}")

    all_rules = aws_rules + multi_csp_stubs
    print(f"  Total rules:         {len(all_rules)}")

    if args.dry_run:
        print("\n--- DRY RUN (no DB writes) ---\n")
        _insert_rules(None, all_rules, dry_run=True)
        print(f"\nDry run complete. {len(all_rules)} rules would be upserted.")
        return

    # Connect and insert
    print("\nConnecting to datasec DB...")
    conn = _get_db_connection()
    try:
        count = _insert_rules(conn, all_rules, dry_run=False)
        conn.commit()
        print(f"\nSeed complete. {count} rules upserted into datasec_rules.")

        # Print summary by CSP
        with conn.cursor() as cur:
            cur.execute(
                "SELECT csp, COUNT(*), COUNT(*) FILTER (WHERE is_active) "
                "FROM datasec_rules GROUP BY csp ORDER BY csp"
            )
            print("\n  CSP       | Total | Active")
            print("  ----------|-------|-------")
            for row in cur.fetchall():
                print(f"  {row[0]:9s} | {row[1]:5d} | {row[2]:5d}")

        # Print summary by category
        with conn.cursor() as cur:
            cur.execute(
                "SELECT category, COUNT(*) "
                "FROM datasec_rules GROUP BY category ORDER BY category"
            )
            print("\n  Category                       | Count")
            print("  -------------------------------|------")
            for row in cur.fetchall():
                print(f"  {row[0]:31s} | {row[1]:5d}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
