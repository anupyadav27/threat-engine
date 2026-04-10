#!/usr/bin/env python3
"""
Enrich CIEM YAML rules with missing fields required for rule_metadata compatibility.

Adds: remediation, domain, compliance_frameworks, risk_score, provider, service
to all CIEM L1 rules that lack these fields.

Usage:
    python enrich_ciem_rules.py                    # dry-run (print stats)
    python enrich_ciem_rules.py --write            # write enriched YAML back
"""

import os
import sys
import copy
import argparse

import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")

# ─── Domain mapping from rule_id prefix ───────────────────────────────────────
# Maps rule_id prefix → (domain, service, provider)
PREFIX_DOMAIN = {
    # AWS CloudTrail
    "iam.ct":        ("iam_security",       "iam",            "aws"),
    "ciem.ct":       ("iam_security",       "iam",            "aws"),
    "threat.ct":     ("threat_detection",    "cloudtrail",     "aws"),
    "storage.ct":    ("data_security",       "s3",             "aws"),
    "compute.ct":    ("compute_security",    "ec2",            "aws"),
    "netsec.ct":     ("network_security",    "vpc",            "aws"),
    "secsvc.ct":     ("security_services",   "guardduty",      "aws"),
    "paas.ct":       ("platform_security",   "lambda",         "aws"),
    "devops.ct":     ("devops_security",     "codebuild",      "aws"),
    "monitor.ct":    ("monitoring",          "cloudwatch",     "aws"),
    "datasec.ct":    ("data_security",       "s3",             "aws"),
    "container.ct":  ("container_security",  "eks",            "aws"),
    # AWS log-source specific
    "vpc.flow":      ("network_security",    "vpc",            "aws"),
    "eks.audit":     ("container_security",  "eks",            "aws"),
    "alb":           ("network_security",    "elbv2",          "aws"),
    "waf":           ("network_security",    "waf",            "aws"),
    "cloudfront":    ("network_security",    "cloudfront",     "aws"),
    "dns":           ("network_security",    "route53",        "aws"),
    "rds.audit":     ("database_security",   "rds",            "aws"),
    "lambda.runtime":("compute_security",    "lambda",         "aws"),
    "guardduty":     ("threat_detection",    "guardduty",      "aws"),
    "s3.access":     ("data_security",       "s3",             "aws"),
    "s3.":           ("data_security",       "s3",             "aws"),
    "network.flow":  ("network_security",    "vpc",            "aws"),
    "network.ct":    ("network_security",    "vpc",            "aws"),
    "lambda.":       ("compute_security",    "lambda",         "aws"),
    "rds.":          ("database_security",   "rds",            "aws"),
    # Azure
    "azure.activity":    ("iam_security",        "azure_ad",       "azure"),
    "azure.aks_audit":   ("container_security",  "aks",            "azure"),
    "azure.nsg_flow":    ("network_security",    "nsg",            "azure"),
    "azure.keyvault":    ("encryption_security", "keyvault",       "azure"),
    "azure.sql_audit":   ("database_security",   "azure_sql",      "azure"),
    "azure.defender":    ("security_services",   "defender",       "azure"),
    "azure.storage":     ("data_security",       "azure_storage",  "azure"),
    "azure.appgw":       ("network_security",    "app_gateway",    "azure"),
    "azure.function":    ("compute_security",    "azure_functions","azure"),
    # GCP
    "gcp.audit":         ("iam_security",        "gcp_iam",        "gcp"),
    "gcp.gke_audit":     ("container_security",  "gke",            "gcp"),
    "gcp.flow":          ("network_security",    "gcp_vpc",        "gcp"),
    "gcp.cloudsql":      ("database_security",   "cloudsql",       "gcp"),
    "gcp.scc":           ("security_services",   "scc",            "gcp"),
    "gcp.data_access":   ("data_security",       "gcs",            "gcp"),
    "gcp.storage":       ("data_security",       "gcs",            "gcp"),
    "gcp.lb":            ("network_security",    "gcp_lb",         "gcp"),
    "gcp.function":      ("compute_security",    "cloud_functions","gcp"),
    # OCI
    "oci.audit":         ("iam_security",        "oci_iam",        "oci"),
    "oci.oke_audit":     ("container_security",  "oke",            "oci"),
    "oci.vcn_flow":      ("network_security",    "oci_vcn",        "oci"),
    "oci.flow":          ("network_security",    "oci_vcn",        "oci"),
    "oci.db_audit":      ("database_security",   "oci_db",         "oci"),
    "oci.cloudguard":    ("security_services",   "cloudguard",     "oci"),
    "oci.waf":           ("network_security",    "oci_waf",        "oci"),
    # IBM
    "ibm.activity":      ("iam_security",        "ibm_iam",        "ibm"),
    "ibm.k8s_audit":     ("container_security",  "iks",            "ibm"),
    "ibm.scc":           ("security_services",   "ibm_scc",        "ibm"),
    "ibm.db_audit":      ("database_security",   "ibm_db",         "ibm"),
}

# ─── Compliance framework mapping by domain ───────────────────────────────────
DOMAIN_COMPLIANCE = {
    "iam_security":       ["CIS", "NIST_800-53", "SOC2", "PCI-DSS", "ISO_27001"],
    "data_security":      ["CIS", "NIST_800-53", "GDPR", "PCI-DSS", "HIPAA", "ISO_27001"],
    "network_security":   ["CIS", "NIST_800-53", "PCI-DSS", "SOC2"],
    "container_security": ["CIS", "NIST_800-53", "SOC2"],
    "compute_security":   ["CIS", "NIST_800-53", "SOC2"],
    "database_security":  ["CIS", "NIST_800-53", "PCI-DSS", "HIPAA", "GDPR"],
    "encryption_security":["CIS", "NIST_800-53", "PCI-DSS", "HIPAA"],
    "threat_detection":   ["NIST_800-53", "SOC2", "MITRE_ATT&CK"],
    "security_services":  ["CIS", "NIST_800-53", "SOC2"],
    "monitoring":         ["CIS", "NIST_800-53", "SOC2"],
    "devops_security":    ["NIST_800-53", "SOC2"],
    "platform_security":  ["CIS", "NIST_800-53", "SOC2"],
}

# ─── Risk score by severity ───────────────────────────────────────────────────
SEVERITY_RISK = {
    "critical": 90,
    "high":     70,
    "medium":   50,
    "low":      25,
    "info":     10,
}

# ─── Remediation templates by action_category ─────────────────────────────────
ACTION_REMEDIATION = {
    "delete":  "Investigate deletion. Verify the actor had authorization. Enable MFA delete where applicable. Review CloudTrail for associated activity.",
    "modify":  "Review the configuration change for unintended exposure. Validate the actor's authorization. Consider enabling change approval workflows.",
    "create":  "Verify the newly created resource follows organizational policy. Check for overly permissive settings. Tag the resource for tracking.",
    "read":    "Verify the accessor has legitimate need-to-know. Review access patterns for anomalies. Consider restricting read permissions.",
    "assume":  "Validate the role assumption is authorized. Check trust policy for overly broad principals. Require external ID for cross-account access.",
    "login":   "Verify the login attempt is legitimate. Enforce MFA for all console access. Review source IP against known ranges.",
    "network": "Review network configuration changes. Validate security group rules follow least-privilege. Block unauthorized ports.",
    "encrypt": "Ensure encryption keys are rotated regularly. Verify KMS policies follow least privilege. Audit decrypt operations.",
    "execute": "Validate function/container execution is authorized. Review execution role permissions. Check for code injection indicators.",
}

# Domain-level fallback remediation
DOMAIN_REMEDIATION = {
    "iam_security":       "Review IAM policies for least privilege. Enable CloudTrail logging. Enforce MFA for privileged operations.",
    "data_security":      "Review data access policies. Enable encryption at rest and in transit. Implement DLP controls.",
    "network_security":   "Review security group and NACL rules. Restrict public access. Enable VPC Flow Logs for monitoring.",
    "container_security": "Review container security policies. Scan images for vulnerabilities. Restrict privileged containers.",
    "compute_security":   "Review instance security configurations. Apply security patches. Restrict instance metadata access.",
    "database_security":  "Review database access controls. Enable audit logging. Encrypt sensitive data at rest.",
    "encryption_security":"Review key management policies. Rotate keys regularly. Audit key usage patterns.",
    "threat_detection":   "Investigate the detected threat. Correlate with other security signals. Initiate incident response if confirmed.",
    "security_services":  "Review security service findings. Prioritize by severity. Remediate root causes.",
    "monitoring":         "Ensure logging and monitoring remain enabled. Investigate any disabling of audit trails.",
    "devops_security":    "Review CI/CD pipeline security. Restrict build environment access. Audit deployment permissions.",
    "platform_security":  "Review platform service configurations. Apply principle of least privilege. Enable logging.",
}


def _resolve_domain(rule_id: str):
    """Resolve domain, service, provider from rule_id prefix."""
    for prefix, (domain, service, provider) in PREFIX_DOMAIN.items():
        if rule_id.startswith(prefix):
            return domain, service, provider
    return "general", "unknown", "aws"


def _resolve_remediation(rule: dict, domain: str) -> str:
    """Build remediation text from action_category or domain."""
    action = rule.get("action_category", "")
    if action in ACTION_REMEDIATION:
        return ACTION_REMEDIATION[action]
    return DOMAIN_REMEDIATION.get(domain, "Investigate the event. Review actor permissions and intent.")


def enrich_rule(rule: dict) -> dict:
    """Add missing fields to a single CIEM rule dict."""
    rule_id = rule.get("rule_id", "")
    if not rule_id:
        return rule

    domain, service, provider = _resolve_domain(rule_id)
    severity = (rule.get("severity") or "medium").lower()

    # Only add fields that are missing — don't overwrite existing values
    # Exception: overwrite "general" domain with a proper mapping
    if "domain" not in rule or rule.get("domain") == "general":
        rule["domain"] = domain
    if "service" not in rule and "log_source_type" not in rule:
        rule["service"] = service
    if "provider" not in rule:
        rule["provider"] = provider
    if "remediation" not in rule:
        rule["remediation"] = _resolve_remediation(rule, domain)
    if "compliance_frameworks" not in rule:
        rule["compliance_frameworks"] = DOMAIN_COMPLIANCE.get(
            rule.get("domain", domain), ["CIS", "NIST_800-53"]
        )
    if "risk_score" not in rule:
        rule["risk_score"] = SEVERITY_RISK.get(severity, 50)

    return rule


def load_yaml(path: str):
    """Load a YAML rule file, returning the raw parsed structure."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def save_yaml(path: str, data):
    """Write YAML back preserving readability."""
    with open(path, "w") as f:
        yaml.dump(
            data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )


def process_file(filepath: str, write: bool = False) -> dict:
    """Process one YAML file: enrich rules, optionally write back.

    Returns stats dict: {total, enriched, skipped, filename}
    """
    data = load_yaml(filepath)
    if data is None:
        return {"total": 0, "enriched": 0, "skipped": 0, "filename": os.path.basename(filepath)}

    # Handle both formats: list-at-root and rules-key wrapper
    rules_list = None
    is_wrapped = False

    if isinstance(data, list):
        rules_list = data
    elif isinstance(data, dict) and "rules" in data:
        rules_list = data["rules"]
        is_wrapped = True
    else:
        # L2/L3 files or unknown format — skip enrichment
        return {"total": 0, "enriched": 0, "skipped": 1, "filename": os.path.basename(filepath)}

    stats = {"total": len(rules_list), "enriched": 0, "skipped": 0, "filename": os.path.basename(filepath)}

    for i, rule in enumerate(rules_list):
        if not isinstance(rule, dict) or "rule_id" not in rule:
            stats["skipped"] += 1
            continue

        before = set(rule.keys())
        enrich_rule(rule)
        after = set(rule.keys())
        if after - before:
            stats["enriched"] += 1

    if write:
        if is_wrapped:
            data["rules"] = rules_list
            save_yaml(filepath, data)
        else:
            save_yaml(filepath, rules_list)

    return stats


def main():
    parser = argparse.ArgumentParser(description="Enrich CIEM YAML rules with missing fields")
    parser.add_argument("--write", action="store_true", help="Write enriched YAML back to disk")
    args = parser.parse_args()

    rules_dir = os.path.abspath(RULES_DIR)
    if not os.path.isdir(rules_dir):
        print(f"Rules directory not found: {rules_dir}")
        sys.exit(1)

    yaml_files = sorted(
        f for f in os.listdir(rules_dir)
        if f.endswith(".yaml") and f.startswith("l1_")
    )

    total_rules = 0
    total_enriched = 0
    total_skipped = 0

    print(f"{'File':<45} {'Rules':>6} {'Enriched':>9} {'Skipped':>8}")
    print("-" * 75)

    for fname in yaml_files:
        fpath = os.path.join(rules_dir, fname)
        stats = process_file(fpath, write=args.write)
        total_rules += stats["total"]
        total_enriched += stats["enriched"]
        total_skipped += stats["skipped"]
        print(f"{stats['filename']:<45} {stats['total']:>6} {stats['enriched']:>9} {stats['skipped']:>8}")

    print("-" * 75)
    print(f"{'TOTAL':<45} {total_rules:>6} {total_enriched:>9} {total_skipped:>8}")
    print()

    if args.write:
        print(f"Wrote enriched rules back to {rules_dir}")
    else:
        print("Dry-run complete. Use --write to apply changes.")


if __name__ == "__main__":
    main()
