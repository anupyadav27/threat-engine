#!/usr/bin/env python3
"""
enrich_ciem_tags.py  — Pass-2 enrichment for CIEM rule YAMLs.

Adds engine-routing and classification fields consumed by:
  • threat engine    → threat_tags, risk_indicators, domain
  • IAM engine       → iam_security, domain (identity_and_access_management)
  • DataSec engine   → data_security
  • UI / reporting   → action_category, log_source_type, posture_category

Reads existing YAMLs (already enriched by enrich_ciem_rules.py), adds the
missing tags, writes back, then optionally syncs to DB.

Sources:
  catalog/rule/azure_rule_ciem/**/*.yaml
  catalog/rule/aws_rule_ciem/**/*.yaml

Usage:
    python3 enrich_ciem_tags.py                    # both providers
    python3 enrich_ciem_tags.py --aws-only
    python3 enrich_ciem_tags.py --azure-only
    python3 enrich_ciem_tags.py --dry-run
    python3 enrich_ciem_tags.py --force            # overwrite existing tags
    python3 enrich_ciem_tags.py --sync-db          # sync to DB after enriching
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
AZURE_CIEM_DIR = ROOT / "catalog" / "rule" / "azure_rule_ciem"
AWS_CIEM_DIR   = ROOT / "catalog" / "rule" / "aws_rule_ciem"
GCP_CIEM_DIR   = ROOT / "catalog" / "rule" / "gcp_rule_ciem"
K8S_CIEM_DIR   = ROOT / "catalog" / "rule" / "k8s_rule_ciem"
OCI_CIEM_DIR   = ROOT / "catalog" / "rule" / "oci_rule_ciem"
IBM_CIEM_DIR   = ROOT / "catalog" / "rule" / "ibm_rule_ciem"

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN mapping  (controlled vocabulary matching live DB values)
# ─────────────────────────────────────────────────────────────────────────────

# Primary: by threat_category
_DOMAIN_BY_CAT: dict[str, str] = {
    "privilege_escalation":    "identity_and_access_management",
    "credential_access":       "identity_and_access_management",
    "persistence":             "identity_and_access_management",
    "identity_manipulation":   "identity_and_access_management",
    "brute_force":             "identity_and_access_management",
    "defense_evasion":         "logging_monitoring_and_alerting",
    "data_exfiltration":       "data_protection_and_privacy",
    "data_destruction":        "data_protection_and_privacy",
    "collection":              "data_protection_and_privacy",
    "lateral_movement":        "network_security_and_connectivity",
    "reconnaissance":          "security_monitoring",
    "execution":               "compute_and_workload_security",
    "supply_chain_compromise": "configuration_and_change_management",
    "impact":                  "impact",
    "web_attack":              "network_security_and_connectivity",
    "injection":               "application_and_api_security",
    "malware":                 "threat_detection",
    "network_scanning":        "network_security_and_connectivity",
    "anomaly":                 "threat_detection",
    "cryptomining":            "compute_and_workload_security",
    "phishing":                "threat_detection",
}

# Override by service (takes priority over threat_category)
_DOMAIN_BY_SERVICE: dict[str, str] = {
    "keyvault":    "cryptography_and_key_management",
    "container":   "container_and_kubernetes_security",
    "network":     "network_security_and_connectivity",
    "netsec":      "network_security_and_connectivity",
    "vpc":         "network_security_and_connectivity",
    "secsvc":      "logging_monitoring_and_alerting",
    "monitor":     "logging_monitoring_and_alerting",
    "datasec":     "data_protection_and_privacy",
    "storage":     "data_protection_and_privacy",
    "s3":          "data_protection_and_privacy",
    "rds":         "data_protection_and_privacy",
    "alb":         "network_security_and_connectivity",
    "cloudfront":  "network_security_and_connectivity",
    "lambda":      "compute_and_workload_security",
    "compute":     "compute_and_workload_security",
    "devops":      "configuration_and_change_management",
    "paas":        "compute_and_workload_security",
    "waf":         "network_security_and_connectivity",
}

# Override by rule_id substring
_DOMAIN_BY_RULE_SUBSTR: list[tuple[str, str]] = [
    ("k8s_",           "container_and_kubernetes_security"),
    ("aks_",           "container_and_kubernetes_security"),
    ("eks_",           "container_and_kubernetes_security"),
    ("container.",     "container_and_kubernetes_security"),
    ("keyvault.",      "cryptography_and_key_management"),
    ("secret",         "cryptography_and_key_management"),
    ("key_backup",     "cryptography_and_key_management"),
    ("nsg_",           "network_security_and_connectivity"),
    ("vnet_",          "network_security_and_connectivity"),
    ("firewall_",      "network_security_and_connectivity"),
    ("sg_all_ports",   "network_security_and_connectivity"),
    ("igw_",           "network_security_and_connectivity"),
    ("vpc.",           "network_security_and_connectivity"),
]


def _get_domain(rule: dict) -> str:
    rid = rule.get("rule_id", "")
    svc = rule.get("service", "")
    cat = rule.get("threat_category", "")

    # Rule substring overrides
    for substr, domain in _DOMAIN_BY_RULE_SUBSTR:
        if substr in rid:
            return domain

    # Service overrides
    if svc in _DOMAIN_BY_SERVICE:
        return _DOMAIN_BY_SERVICE[svc]

    # Threat category
    return _DOMAIN_BY_CAT.get(cat, "threat_detection")


# ─────────────────────────────────────────────────────────────────────────────
# ACTION_CATEGORY
# ─────────────────────────────────────────────────────────────────────────────

# Map patterns found in rule_id / operation to action_category
_ACTION_PATTERNS: list[tuple[str, str]] = [
    # Privilege escalation
    ("elevate_access",         "privilege_escalation"),
    ("privilege_escalation",   "privilege_escalation"),
    ("admin_api_call",         "privilege_escalation"),
    ("global_admin_role_add",  "privilege_escalation"),
    ("directory_role_member",  "privilege_escalation"),
    # Authentication / brute force
    ("console_login_failure",  "authentication"),
    ("brute_force",            "brute_force"),
    ("mfa_update",             "authentication"),
    ("auth_method",            "authentication"),
    # Read operations
    ("list_keys",              "read"),
    ("_read",                  "read"),
    ("_get",                   "read"),
    ("_list",                  "read"),
    ("admin_credential_list",  "read"),
    ("user_credential_list",   "read"),
    ("access_key_last_used",   "read"),
    ("get_object",             "read"),
    ("list_objects",           "read"),
    ("get_acl",                "read"),
    ("get_policy",             "read"),
    ("access_profile_read",    "read"),
    ("get_console_screenshot",  "read"),
    ("get_password_data",      "read"),
    ("key_backup",             "read"),
    ("hsm_key_backup",         "read"),
    # Delete operations
    ("_delete",                "delete"),
    ("_purge",                 "delete"),
    ("_remove",                "delete"),
    ("terminate_instance",     "delete"),
    ("delete_bucket",          "delete"),
    ("stop_logging",           "delete"),
    ("disable_guardduty",      "delete"),
    # Execute / run
    ("pod_exec",               "execute"),
    ("run_command",            "execute"),
    ("vm_run_command",         "execute"),
    ("vm_extension_write",     "execute"),
    ("run_instances",          "execute"),
    ("ec2_run",                "execute"),
    ("lambda.",                "execute"),
    # Network
    ("nsg_",                   "network"),
    ("vnet_peering",           "network"),
    ("firewall_rule",          "network"),
    ("igw_attached",           "network"),
    ("sg_all_ports",           "network"),
    ("global_accelerator",     "network"),
    ("route53",                "network"),
    ("cloudfront",             "network"),
    ("netsec.",                "network"),
    # Exfiltration
    ("exfil",                  "exfiltration"),
    ("data_exfil",             "exfiltration"),
    # C2
    ("brute_force",            "brute_force"),
    ("access_denied_spike",    "reconnaissance"),
    ("enumerate_s3",           "reconnaissance"),
    # Create / write (default for write ops)
    ("_write",                 "create"),
    ("_create",                "create"),
    ("_assign",                "create"),
    ("_put",                   "create"),
    ("_add",                   "create"),
    ("_import",                "create"),
    ("_register",              "create"),
    ("_enable",                "create"),
    # Modify
    ("_update",                "modify"),
    ("_modify",                "modify"),
    ("_change",                "modify"),
    ("_reimage",               "modify"),
    ("_capture",               "modify"),
    ("stop_logging",           "modify"),
    ("update_trail",           "modify"),
    # Audit / monitoring
    ("cloudtrail",             "audit_activity"),
]

# threat_category → action_category fallback
_ACTION_BY_CAT: dict[str, str] = {
    "privilege_escalation":  "privilege_escalation",
    "defense_evasion":       "modify",
    "credential_access":     "read",
    "lateral_movement":      "network",
    "reconnaissance":        "reconnaissance",
    "brute_force":           "brute_force",
    "data_exfiltration":     "exfiltration",
    "data_destruction":      "delete",
    "execution":             "execute",
    "persistence":           "create",
    "identity_manipulation": "create",
    "collection":            "read",
    "impact":                "delete",
    "supply_chain_compromise": "create",
}


def _get_action_category(rule: dict) -> str:
    rid = rule.get("rule_id", "")
    for pattern, action in _ACTION_PATTERNS:
        if pattern in rid:
            return action
    # Check check_config operation value
    cc = rule.get("check_config", {}) or {}
    op = ""
    conds = cc.get("conditions", {}) or {}
    for c in conds.get("all", []):
        if c.get("field") == "operation":
            op = str(c.get("value", "")).lower()
            break
    if op:
        for pattern, action in _ACTION_PATTERNS:
            if pattern in op:
                return action
    cat = rule.get("threat_category", "")
    return _ACTION_BY_CAT.get(cat, "create")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT_TAGS  (MITRE technique IDs + category tags)
# ─────────────────────────────────────────────────────────────────────────────

# Extra semantic tags per threat_category
_EXTRA_TAGS_BY_CAT: dict[str, list[str]] = {
    "privilege_escalation":  ["cloud_iam", "privilege_escalation"],
    "credential_access":     ["credential_access", "secret_exposure"],
    "persistence":           ["persistence", "backdoor"],
    "identity_manipulation": ["cloud_iam", "identity_manipulation"],
    "defense_evasion":       ["defense_evasion", "log_tampering"],
    "data_exfiltration":     ["data_exfiltration", "data_loss"],
    "data_destruction":      ["data_destruction", "impact"],
    "collection":            ["data_collection", "sensitive_data"],
    "lateral_movement":      ["lateral_movement", "cloud_pivot"],
    "reconnaissance":        ["reconnaissance", "cloud_enumeration"],
    "execution":             ["remote_execution", "cloud_exec"],
    "supply_chain_compromise": ["supply_chain", "container_compromise"],
    "impact":                ["impact", "availability"],
    "brute_force":           ["brute_force", "credential_stuffing"],
}

# Extra tags per service
_EXTRA_TAGS_BY_SERVICE: dict[str, list[str]] = {
    "iam":          ["cloud_iam", "identity"],
    "authorization": ["rbac", "role_assignment"],
    "identity":     ["cloud_iam", "conditional_access"],
    "keyvault":     ["secrets", "cryptography"],
    "storage":      ["storage_access", "data"],
    "container":    ["kubernetes", "container_security"],
    "network":      ["network_security"],
    "secsvc":       ["security_service", "audit_log"],
    "monitor":      ["audit_log", "monitoring"],
    "datasec":      ["data_security"],
    "ciem":         ["ciem_correlation", "attack_chain"],
    "threat":       ["threat_detection"],
    "guardduty":    ["threat_detection", "guardduty"],
    "s3":           ["storage_access", "s3_data"],
    "vpc":          ["network_security", "vpc"],
    "devops":       ["cicd", "devops_security"],
    "waf":          ["waf", "web_security"],
}


def _get_threat_tags(rule: dict) -> list[str]:
    techniques = rule.get("mitre_techniques") or []
    cat = rule.get("threat_category", "")
    svc = rule.get("service", "")

    tags = list(techniques)  # Start with MITRE technique IDs

    # Add parent techniques (e.g., T1098 for T1098.003)
    parents = set()
    for t in techniques:
        parent = t.split(".")[0]
        if parent != t:
            parents.add(parent)
    tags.extend(sorted(parents))

    # Category tags
    tags.extend(_EXTRA_TAGS_BY_CAT.get(cat, []))

    # Service tags
    tags.extend(_EXTRA_TAGS_BY_SERVICE.get(svc, []))

    # Deduplicate, preserve order
    seen: set[str] = set()
    result = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# IAM_SECURITY
# ─────────────────────────────────────────────────────────────────────────────

_IAM_RELEVANT_CATS = {
    "privilege_escalation", "credential_access", "persistence",
    "identity_manipulation", "brute_force",
}

_IAM_MODULE_PATTERNS: list[tuple[str, str]] = [
    ("least_privilege",      "least_privilege"),
    ("role_assignment",      "role_management"),
    ("role_definition",      "role_management"),
    ("directory_role",       "role_management"),
    ("elevate_access",       "role_management"),
    ("privilege_escalation", "role_management"),
    ("role_management",      "role_management"),
    ("pim_",                 "role_management"),
    ("policy_",              "policy_analysis"),
    ("_policy",              "policy_analysis"),
    ("permission",           "policy_analysis"),
    ("consent",              "policy_analysis"),
    ("blueprint",            "policy_analysis"),
    ("mfa",                  "mfa"),
    ("auth_method",          "mfa"),
    ("hardware_mfa",         "mfa"),
    ("password",             "password_policy"),
    ("login_profile",        "password_policy"),
    ("federation",           "access_control"),
    ("domain_federation",    "access_control"),
    ("external_identity",    "access_control"),
    ("saml",                 "access_control"),
    ("oidc",                 "access_control"),
    ("sso_",                 "access_control"),
    ("conditional_access",   "access_control"),
    ("access_key",           "access_control"),
    ("app_credential",       "access_control"),
    ("service_principal_credential", "access_control"),
    ("federated_credential", "access_control"),
]


def _get_iam_security(rule: dict) -> dict:
    cat = rule.get("threat_category", "")
    rid = rule.get("rule_id", "")
    svc = rule.get("service", "")

    # IAM-relevant services
    is_iam_svc = svc in ("iam", "authorization", "identity", "ciem")
    is_iam_cat = cat in _IAM_RELEVANT_CATS

    if not (is_iam_svc or is_iam_cat):
        return {"applicable": False, "modules": []}

    # Derive modules from rule_id patterns
    text = rid.lower()
    modules: list[str] = []
    for pattern, module in _IAM_MODULE_PATTERNS:
        if pattern in text and module not in modules:
            modules.append(module)

    # Always include access_control for IAM-relevant rules
    if "access_control" not in modules:
        modules.append("access_control")

    return {"applicable": True, "modules": modules}


# ─────────────────────────────────────────────────────────────────────────────
# DATA_SECURITY
# ─────────────────────────────────────────────────────────────────────────────

_DS_RELEVANT_CATS = {
    "data_exfiltration", "data_destruction", "collection", "credential_access",
}

_DS_RELEVANT_SERVICES = {
    "keyvault", "storage", "s3", "rds", "datasec", "secsvc",
}

# Rule patterns that indicate data-security relevance
_DS_RELEVANT_PATTERNS = [
    "secret", "key_", "_key", "storage", "blob", "bucket", "object",
    "snapshot", "backup", "database", "rds_", "elasticache", "redshift",
    "lifecycle_policy", "management_policy", "container_public",
    "encryption", "kms",
]

# Datasec module mapping
_DS_MODULES_BY_PATTERN: list[tuple[str, str]] = [
    ("secret",          "secrets_management"),
    ("keyvault",        "secrets_management"),
    ("key_",            "secrets_management"),
    ("_key",            "secrets_management"),
    ("kms",             "secrets_management"),
    ("encryption",      "secrets_management"),
    ("storage",         "data_access_governance"),
    ("blob",            "data_access_governance"),
    ("bucket",          "data_access_governance"),
    ("object",          "data_access_governance"),
    ("_data",           "data_access_governance"),
    ("s3.",             "data_access_governance"),
    ("database",        "database_security"),
    ("rds",             "database_security"),
    ("redshift",        "database_security"),
    ("elasticache",     "database_security"),
    ("snapshot",        "backup_and_recovery"),
    ("backup",          "backup_and_recovery"),
    ("lifecycle",       "data_lifecycle_management"),
    ("management_policy", "data_lifecycle_management"),
    ("data_destruction", "data_loss_prevention"),
    ("delete_object",    "data_loss_prevention"),
    ("delete_multiple",  "data_loss_prevention"),
    ("exfil",           "data_loss_prevention"),
]

# Data impact boilerplate by category/service
_DS_IMPACT_TEMPLATES: dict[str, dict] = {
    "secrets": {
        "pci":   "PCI DSS Requirement 3.4 — Sensitive authentication data must be protected",
        "gdpr":  "GDPR Article 32 — Appropriate technical measures to protect personal data",
        "hipaa": "§164.312(e)(2)(ii) — Encryption of ePHI in transit and at rest",
    },
    "storage": {
        "pci":   "PCI DSS Requirement 3.1 — Minimize cardholder data storage",
        "gdpr":  "GDPR Article 25 — Data protection by design; minimize data exposure",
        "hipaa": "§164.312(a)(1) — Access controls on data repositories containing ePHI",
    },
    "database": {
        "pci":   "PCI DSS Requirement 7 — Restrict access to cardholder data by business need",
        "gdpr":  "GDPR Article 25 — Data protection by design and by default",
        "hipaa": "§164.312(a)(1) — Access control for ePHI data systems",
    },
    "iam": {
        "pci":   "PCI DSS Requirement 7.1 — Limit access to system components to only those individuals whose job requires such access",
        "gdpr":  "GDPR Article 25 — Data protection by design and by default",
        "hipaa": "§164.312(a)(1) — Implement technical policies for access to ePHI",
    },
    "network": {
        "pci":   "PCI DSS Requirement 1.2 — Build firewall and router configuration to restrict connections",
        "gdpr":  "GDPR Article 32 — Appropriate technical and organizational security measures",
        "hipaa": "§164.312(e)(1) — Implement technical security measures to guard against unauthorized access",
    },
    "default": {
        "pci":   "PCI DSS Requirement 12.3 — Implement security awareness program and protect systems",
        "gdpr":  "GDPR Article 32 — Appropriate technical and organizational measures for data security",
        "hipaa": "§164.306(a) — Ensure confidentiality, integrity, and availability of ePHI",
    },
}

_DS_CATEGORIES_BY_CAT: dict[str, list[str]] = {
    "data_exfiltration":  ["data_exfiltration", "unauthorized_access"],
    "data_destruction":   ["data_loss", "availability_impact"],
    "collection":         ["sensitive_data_access", "unauthorized_access"],
    "credential_access":  ["secrets_exposure", "credential_theft"],
}


def _get_data_security(rule: dict) -> dict:
    cat = rule.get("threat_category", "")
    svc = rule.get("service", "")
    rid = rule.get("rule_id", "").lower()

    # Check applicability
    is_ds_cat = cat in _DS_RELEVANT_CATS
    is_ds_svc = svc in _DS_RELEVANT_SERVICES
    is_ds_pattern = any(p in rid for p in _DS_RELEVANT_PATTERNS)

    if not (is_ds_cat or is_ds_svc or is_ds_pattern):
        return {"applicable": False}

    # Derive modules
    modules: list[str] = []
    for pattern, module in _DS_MODULES_BY_PATTERN:
        if pattern in rid and module not in modules:
            modules.append(module)
    if cat == "data_exfiltration" and "data_loss_prevention" not in modules:
        modules.append("data_loss_prevention")
    if cat == "data_destruction" and "data_loss_prevention" not in modules:
        modules.append("data_loss_prevention")
    if not modules:
        modules.append("data_access_governance")

    # Categories
    categories = _DS_CATEGORIES_BY_CAT.get(cat, ["sensitive_data_access"])

    # Impact template
    if "secret" in rid or svc == "keyvault" or "kms" in rid:
        impact = _DS_IMPACT_TEMPLATES["secrets"]
    elif "storage" in rid or "blob" in rid or "bucket" in rid or svc in ("storage", "s3"):
        impact = _DS_IMPACT_TEMPLATES["storage"]
    elif "database" in rid or "rds" in rid or "redshift" in rid:
        impact = _DS_IMPACT_TEMPLATES["database"]
    else:
        impact = _DS_IMPACT_TEMPLATES["default"]

    # Priority by severity
    sev = rule.get("severity", "medium")
    priority_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    priority = priority_map.get(sev, "medium")

    # Sensitive data context
    sensitive_context = (
        f"Unauthorized {cat.replace('_', ' ')} on {svc} resources must be detected to prevent:\n"
        "    - Data loss and regulatory compliance violations\n"
        "    - Unauthorized exposure of sensitive and personal data\n"
        "    - Violation of data residency and retention policies"
    )

    return {
        "applicable": True,
        "modules": modules,
        "categories": categories,
        "priority": priority,
        "impact": impact,
        "sensitive_data_context": sensitive_context,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RISK_INDICATORS
# ─────────────────────────────────────────────────────────────────────────────

_ACTOR_TYPE_BY_SERVICE: dict[str, str] = {
    "iam":           "iam_user_or_role",
    "authorization": "user_or_service_principal",
    "identity":      "user_or_service_principal",
    "keyvault":      "service_principal_or_app",
    "container":     "service_account_or_workload",
    "devops":        "cicd_service_principal",
    "guardduty":     "external_threat_actor",
}

_TARGET_TYPE_BY_SERVICE: dict[str, str] = {
    "iam":           "iam_identity",
    "authorization": "rbac_assignment",
    "identity":      "entra_id_identity",
    "keyvault":      "secret_or_key",
    "storage":       "storage_account",
    "s3":            "s3_bucket",
    "container":     "kubernetes_workload",
    "network":       "network_resource",
    "netsec":        "network_resource",
    "secsvc":        "security_service",
    "monitor":       "audit_log",
    "vpc":           "network_resource",
    "rds":           "database",
    "datasec":       "data_resource",
    "compute":       "compute_instance",
    "lambda":        "serverless_function",
    "devops":        "cicd_pipeline",
    "guardduty":     "cloud_workload",
}

_BLAST_RADIUS_BY_SERVICE: dict[str, str] = {
    "authorization": "subscription",
    "identity":      "tenant",
    "iam":           "account",
    "ciem":          "tenant_or_account",
    "threat":        "multi_resource",
}

_STEALTH_RISK: dict[str, str] = {
    "defense_evasion": "critical",
    "persistence":     "high",
    "credential_access": "high",
    "privilege_escalation": "high",
    "lateral_movement": "medium",
    "data_exfiltration": "high",
    "data_destruction": "medium",
    "collection":       "medium",
    "reconnaissance":   "low",
    "identity_manipulation": "high",
    "execution":        "medium",
    "impact":           "low",
}


def _get_risk_indicators(rule: dict) -> dict:
    svc = rule.get("service", "")
    cat = rule.get("threat_category", "")
    act = rule.get("action_category", "")

    actor_type = _ACTOR_TYPE_BY_SERVICE.get(svc, "cloud_principal")
    target_type = _TARGET_TYPE_BY_SERVICE.get(svc, "cloud_resource")
    blast_radius = _BLAST_RADIUS_BY_SERVICE.get(svc, "resource_group")
    stealth_risk = _STEALTH_RISK.get(cat, "medium")

    # Infer action_type from action_category
    action_map = {
        "create": "write",
        "modify": "write",
        "delete": "destructive",
        "read": "read",
        "execute": "execution",
        "privilege_escalation": "privilege_change",
        "exfiltration": "data_transfer",
        "authentication": "authentication",
        "brute_force": "authentication",
        "network": "network_change",
        "reconnaissance": "discovery",
    }
    action_type = action_map.get(act, "write")

    return {
        "actor_type":    actor_type,
        "action_type":   action_type,
        "target_type":   target_type,
        "blast_radius":  blast_radius,
        "stealth_risk":  stealth_risk,
    }


# ─────────────────────────────────────────────────────────────────────────────
# LOG_SOURCE_TYPE  (top-level, mirrors check_config)
# ─────────────────────────────────────────────────────────────────────────────

def _get_log_source_type(rule: dict) -> str:
    """Extract log_source_type from check_config for top-level field."""
    cc = rule.get("check_config", {}) or {}
    return cc.get("log_source_type", "")


# ─────────────────────────────────────────────────────────────────────────────
# POSTURE_CATEGORY  (for check-engine filtering)
# ─────────────────────────────────────────────────────────────────────────────

_POSTURE_BY_CAT: dict[str, str] = {
    "privilege_escalation":  "iam_posture",
    "credential_access":     "iam_posture",
    "persistence":           "iam_posture",
    "identity_manipulation": "iam_posture",
    "brute_force":           "iam_posture",
    "defense_evasion":       "security_posture",
    "data_exfiltration":     "data_security_posture",
    "data_destruction":      "data_security_posture",
    "collection":            "data_security_posture",
    "lateral_movement":      "network_posture",
    "reconnaissance":        "threat_posture",
    "execution":             "workload_posture",
    "supply_chain_compromise": "workload_posture",
    "impact":                "workload_posture",
    "web_attack":            "threat_posture",
    "injection":             "threat_posture",
    "malware":               "threat_posture",
    "cryptomining":          "threat_posture",
    "anomaly":               "threat_posture",
    "network_scanning":      "network_posture",
    "phishing":              "threat_posture",
}


# ─────────────────────────────────────────────────────────────────────────────
# YAML writer  (reuse from enrich_ciem_rules.py logic)
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    if "\n" in value:
        lines = value.rstrip("\n").split("\n")
        return "|\n" + "\n".join("  " + ln for ln in lines)
    if any(c in value for c in (':', '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_rule(data: dict) -> str:
    lines = []

    SCALAR_FIELDS = [
        "rule_id", "service", "provider", "check_type", "severity",
        "title", "description",
    ]
    for field in SCALAR_FIELDS:
        if field in data:
            lines.append(f"{field}: {_yaml_str(str(data[field]))}")

    if "rationale" in data:
        lines.append(f"rationale: {_yaml_str(data['rationale'])}")

    if "threat_category" in data:
        lines.append(f"threat_category: {data['threat_category']}")

    if "mitre_tactics" in data:
        lines.append("mitre_tactics:")
        for t in data["mitre_tactics"]:
            lines.append(f"- {t}")

    if "mitre_techniques" in data:
        lines.append("mitre_techniques:")
        for t in data["mitre_techniques"]:
            lines.append(f"- {t}")

    if "risk_score" in data:
        lines.append(f"risk_score: {data['risk_score']}")

    for field in ("resource", "source", "is_active"):
        if field in data:
            val = data[field]
            if isinstance(val, bool):
                lines.append(f"{field}: {'true' if val else 'false'}")
            else:
                lines.append(f"{field}: {_yaml_str(str(val))}")

    # Engine-routing / classification fields
    if "domain" in data:
        lines.append(f"domain: {data['domain']}")
    if "action_category" in data:
        lines.append(f"action_category: {data['action_category']}")
    if "log_source_type" in data:
        lines.append(f"log_source_type: {data['log_source_type']}")
    if "posture_category" in data:
        lines.append(f"posture_category: {data['posture_category']}")

    # threat_tags (JSONB list)
    if "threat_tags" in data:
        tags = data["threat_tags"]
        if tags:
            lines.append("threat_tags:")
            for t in tags:
                lines.append(f"- {t}")
        else:
            lines.append("threat_tags: []")

    # risk_indicators
    if "risk_indicators" in data:
        ri = data["risk_indicators"]
        if ri:
            lines.append("risk_indicators:")
            for k, v in ri.items():
                lines.append(f"  {k}: {v}")

    # iam_security
    if "iam_security" in data:
        iam = data["iam_security"]
        lines.append("iam_security:")
        lines.append(f"  applicable: {'true' if iam.get('applicable') else 'false'}")
        mods = iam.get("modules", [])
        if mods:
            lines.append("  modules:")
            for m in mods:
                lines.append(f"  - {m}")
        else:
            lines.append("  modules: []")

    # data_security
    if "data_security" in data:
        ds = data["data_security"]
        lines.append("data_security:")
        lines.append(f"  applicable: {'true' if ds.get('applicable') else 'false'}")
        if ds.get("applicable"):
            mods = ds.get("modules", [])
            if mods:
                lines.append("  modules:")
                for m in mods:
                    lines.append(f"  - {m}")
            cats = ds.get("categories", [])
            if cats:
                lines.append("  categories:")
                for c in cats:
                    lines.append(f"  - {c}")
            if "priority" in ds:
                lines.append(f"  priority: {ds['priority']}")
            impact = ds.get("impact", {})
            if impact:
                lines.append("  impact:")
                for k, v in impact.items():
                    lines.append(f"    {k}: {_yaml_str(v)}")
            sc = ds.get("sensitive_data_context", "")
            if sc:
                lines.append(f"  sensitive_data_context: {_yaml_str(sc)}")

    # compliance_frameworks
    if "compliance_frameworks" in data:
        cf = data["compliance_frameworks"] or {}
        if cf:
            lines.append("compliance_frameworks:")
            for fw, controls in cf.items():
                lines.append(f"  {fw}:")
                for c in (controls or []):
                    lines.append(f"  - {c}")
        else:
            lines.append("compliance_frameworks: {}")

    # detection_events — preserve existing; patch_mitre_rationale.py will add if missing
    if "detection_events" in data:
        lines.append("detection_events:")
        for de in (data["detection_events"] or []):
            lines.append(f"- {_yaml_str(str(de))}")

    # remediation
    if "remediation" in data:
        lines.append(f"remediation: {_yaml_str(data['remediation'])}")

    # references
    if "references" in data:
        lines.append("references:")
        for ref in data["references"]:
            lines.append(f"- {ref}")

    # check_config
    if "check_config" in data:
        cc_yaml = yaml.dump(
            {"check_config": data["check_config"]},
            default_flow_style=False,
            allow_unicode=True,
        ).rstrip()
        lines.append(cc_yaml)

    if "version" in data:
        lines.append(f"version: '{data['version']}'")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment
# ─────────────────────────────────────────────────────────────────────────────

def enrich_file(path: Path, dry_run: bool, force: bool) -> str:
    raw = path.read_text(encoding="utf-8")
    rule = yaml.safe_load(raw)
    if not isinstance(rule, dict):
        return "SKIP"

    changed = False

    def _set(key: str, value: Any) -> None:
        nonlocal changed
        if key not in rule or force or rule[key] is None:
            rule[key] = value
            changed = True

    # Derive action_category first (used by risk_indicators)
    action_cat = _get_action_category(rule)
    _set("action_category", action_cat)

    # Now set action_category on rule so risk_indicators can read it
    rule_with_action = dict(rule)
    rule_with_action["action_category"] = action_cat

    _set("domain",          _get_domain(rule))
    _set("log_source_type", _get_log_source_type(rule))
    _set("posture_category", _POSTURE_BY_CAT.get(rule.get("threat_category", ""), "threat_posture"))
    _set("threat_tags",     _get_threat_tags(rule))
    _set("risk_indicators", _get_risk_indicators(rule_with_action))
    _set("iam_security",    _get_iam_security(rule))
    _set("data_security",   _get_data_security(rule))

    if not changed:
        return "SKIP (already tagged)"

    if dry_run:
        return f"DRY  ({rule.get('rule_id', path.name)})"

    path.write_text(_dump_rule(rule), encoding="utf-8")
    return "OK"


# ─────────────────────────────────────────────────────────────────────────────
# DB sync
# ─────────────────────────────────────────────────────────────────────────────

_DB_UPDATE_SQL = """
UPDATE rule_metadata SET
    domain           = %s,
    action_category  = %s,
    log_source_type  = %s,
    threat_tags      = %s,
    risk_indicators  = %s,
    iam_security     = %s,
    data_security    = %s,
    posture_category = %s,
    updated_at       = NOW()
WHERE rule_id = %s
  AND customer_id IS NULL AND tenant_id IS NULL
"""


def _sync_to_db(rules: list[dict], provider: str) -> None:
    import psycopg2
    import psycopg2.extras

    conn = psycopg2.connect(
        host     = os.getenv("CHECK_DB_HOST",     "localhost"),
        port     = int(os.getenv("CHECK_DB_PORT", "5432")),
        dbname   = os.getenv("CHECK_DB_NAME",     "threat_engine_check"),
        user     = os.getenv("CHECK_DB_USER",     "postgres"),
        password = os.getenv("CHECK_DB_PASSWORD", ""),
    )
    J = psycopg2.extras.Json
    batch = []
    for r in rules:
        batch.append((
            r.get("domain"),
            r.get("action_category"),
            r.get("log_source_type"),
            J(r.get("threat_tags") or []),
            J(r.get("risk_indicators") or {}),
            J(r.get("iam_security") or {}),
            J(r.get("data_security") or {}),
            r.get("posture_category"),
            r["rule_id"],
        ))
        if len(batch) >= 200:
            with conn.cursor() as cur:
                cur.executemany(_DB_UPDATE_SQL, batch)
            conn.commit()
            batch = []
    if batch:
        with conn.cursor() as cur:
            cur.executemany(_DB_UPDATE_SQL, batch)
        conn.commit()
    conn.close()
    print(f"  DB updated: {len(rules)} {provider} rules")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Add engine-routing tags to CIEM rule YAMLs")
    p.add_argument("--aws-only",   action="store_true")
    p.add_argument("--azure-only", action="store_true")
    p.add_argument("--gcp-only",   action="store_true")
    p.add_argument("--k8s-only",   action="store_true")
    p.add_argument("--oci-only",   action="store_true")
    p.add_argument("--ibm-only",   action="store_true")
    p.add_argument("--dry-run",    action="store_true")
    p.add_argument("--force",      action="store_true", help="Overwrite existing tags")
    p.add_argument("--sync-db",    action="store_true", help="Sync tag updates to DB")
    args = p.parse_args()

    _non_aws   = args.azure_only or args.gcp_only or args.k8s_only or args.oci_only or args.ibm_only
    _non_azure = args.aws_only   or args.gcp_only or args.k8s_only or args.oci_only or args.ibm_only
    _non_gcp   = args.aws_only   or args.azure_only or args.k8s_only or args.oci_only or args.ibm_only
    _non_k8s   = args.aws_only   or args.azure_only or args.gcp_only  or args.oci_only or args.ibm_only
    _non_oci   = args.aws_only   or args.azure_only or args.gcp_only  or args.k8s_only or args.ibm_only
    _non_ibm   = args.aws_only   or args.azure_only or args.gcp_only  or args.k8s_only or args.oci_only

    dirs: list[tuple[str, Path]] = []
    if not _non_aws:
        dirs.append(("aws",   AWS_CIEM_DIR))
    if not _non_azure:
        dirs.append(("azure", AZURE_CIEM_DIR))
    if not _non_gcp:
        dirs.append(("gcp",   GCP_CIEM_DIR))
    if not _non_k8s:
        dirs.append(("k8s",   K8S_CIEM_DIR))
    if not _non_oci:
        dirs.append(("oci",   OCI_CIEM_DIR))
    if not _non_ibm:
        dirs.append(("ibm",   IBM_CIEM_DIR))

    total = ok = skip = err = 0
    for provider, d in dirs:
        yamls = sorted(d.rglob("*.yaml"))
        print(f"\n── {d.name}  ({len(yamls)} files) ─────────────────────────")
        enriched_rules = []
        for path in yamls:
            total += 1
            try:
                status = enrich_file(path, dry_run=args.dry_run, force=args.force)
                if status.startswith("OK"):
                    ok += 1
                    if args.sync_db and not args.dry_run:
                        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                        enriched_rules.append(rule)
                else:
                    skip += 1
            except Exception as exc:
                err += 1
                print(f"  ERROR  {path.name}: {exc}")

        if args.sync_db and enriched_rules and not args.dry_run:
            _sync_to_db(enriched_rules, provider)

    print(f"\n── Summary ──────────────────────────────────────────")
    print(f"  Total   : {total}")
    print(f"  Tagged  : {ok}")
    print(f"  Skipped : {skip}")
    print(f"  Errors  : {err}")
    if args.dry_run:
        print("  (dry-run — no files written)")


if __name__ == "__main__":
    main()
