#!/usr/bin/env python3
"""
step1_build_metadata.py
=======================
Phase 1: Generate rule metadata YAMLs for all 836 new rules from CSV.

Pure-code, no AI. Deterministically maps:
  - compliance_ids column → compliance_frameworks dict  (20 framework keys)
  - rule_id pattern       → domain, posture_category, subcategory
  - rule suffix           → mitre_tactics, mitre_techniques, risk_score
  - rule_type             → check_type (log vs resource), engine
  - csp + service         → log_source_type (CIEM rules)

Output: catalog/rule/{csp}_rule_metadata/{service}/{rule_id}.yaml
        catalog/rule/metadata_generation_report.json

Usage:
    python3 catalog/rule/step1_build_metadata.py             # dry-run
    python3 catalog/rule/step1_build_metadata.py --apply     # write files
    python3 catalog/rule/step1_build_metadata.py --apply --csp aws
    python3 catalog/rule/step1_build_metadata.py --apply --type ciem
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
CSV_PATH = ROOT / "complaince_csv" / "new_rules_deduplicated.csv"

APPLY      = "--apply" in sys.argv
OVERWRITE  = "--overwrite" in sys.argv
FILTER_CSP = None
FILTER_TYPE = None
for i, arg in enumerate(sys.argv):
    if arg == "--csp" and i + 1 < len(sys.argv):
        FILTER_CSP = sys.argv[i + 1].lower()
    if arg == "--type" and i + 1 < len(sys.argv):
        FILTER_TYPE = sys.argv[i + 1].lower()

if not APPLY:
    print("*** DRY-RUN — pass --apply to write files ***")

# ─────────────────────────────────────────────────────────────────────────────
# Compliance framework key mapping
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK_KEY_MAP: dict[str, str] = {
    "PCI_DSS":              "pci_dss_v4",
    "NIST_800_171":         "nist_800_171",
    "NIST_800_53":          "nist_800_53_r5",
    "CIS_AWS":              "cis_aws_v3",
    "CIS_AZURE":            "cis_azure_v2",
    "CIS_ALICLOUD":         "cis_alicloud",
    "CIS_GCP":              "cis_gcp",
    "CIS_OCI":              "cis_oci",
    "CIS_IBM":              "cis_ibm",
    "CIS_K8S":              "cis_k8s",
    "CIS":                  "cis_controls_v8",
    "CANADA_PBMM":          "canada_pbmm",
    "ISO27001_2022":        "iso_27001_2022",
    "SOC2":                 "soc2_type2",
    "HIPAA":                "hipaa",
    "GDPR":                 "gdpr",
    "FedRAMP_Moderate":     "fedramp_moderate",
    "RBI_BANK":             "rbi_bank",
    "RBI_NBFC":             "rbi_nbfc",
    "CISA_CE":              "cisa_ce",
    "CSPM_BEST_PRACTICE":   None,   # no specific control ID
}

def parse_compliance(frameworks_str: str, compliance_ids_str: str) -> dict[str, list[str]]:
    """
    Parse CSV compliance_ids like 'PCI_DSS/10.2.2;NIST_800_171/3.1.8'
    into {'pci_dss_v4': ['10.2.2'], 'nist_800_171': ['3.1.8']}

    Also handles bare frameworks like 'CSPM_BEST_PRACTICE' with no control.
    """
    result: dict[str, list[str]] = {}

    # Primary source: compliance_ids column (most specific)
    if compliance_ids_str and compliance_ids_str.strip():
        for item in compliance_ids_str.split(";"):
            item = item.strip()
            if not item:
                continue
            slash = item.find("/")
            if slash >= 0:
                fw_raw  = item[:slash].strip()
                control = item[slash + 1:].strip()
            else:
                fw_raw  = item.strip()
                control = None
            mapped = FRAMEWORK_KEY_MAP.get(fw_raw)
            if mapped is None:
                continue  # CSPM_BEST_PRACTICE or unknown → no entry
            if control:
                result.setdefault(mapped, []).append(control)
            else:
                result.setdefault(mapped, [])

    # Secondary: frameworks column — add key if not already present
    if frameworks_str:
        for fw_raw in frameworks_str.split(";"):
            fw_raw = fw_raw.strip()
            if not fw_raw:
                continue
            mapped = FRAMEWORK_KEY_MAP.get(fw_raw)
            if mapped and mapped not in result:
                result[mapped] = []

    return result

# ─────────────────────────────────────────────────────────────────────────────
# Domain + posture_category inference
# ─────────────────────────────────────────────────────────────────────────────

_DOMAIN_PATTERNS: list[tuple[list[str], str]] = [
    # Patterns matched against lowercase rule_id
    (["iam", "ram", "aad", "rbac", "role", "policy", "permission", "access_key",
      "mfa", "auth", "privilege", "credential", "serviceid", "service_id",
      "trusted_profile", "access_group", "user_login", "login_profile",
      "inactivity", "dormant", "replay", "brute_force", "login_attempt",
      "console_login", "account_invite"], "identity_and_access_management"),
    (["log", "audit", "trail", "monitor", "alert", "activity_log", "actiontrail",
      "cloudtrail", "cloudwatch", "flowlog", "metric", "notification", "alarm",
      "siem", "soc", "detection", "event", "log_review", "timestamp",
      "log_integrity", "log_export", "retention_update"], "logging_monitoring_and_alerting"),
    (["firewall", "network", "vpc", "subnet", "security_group", "nacl", "acl",
      "ingress", "egress", "port", "flow_log", "dns", "routing", "load_balancer",
      "waf", "vpn", "gateway", "endpoint", "peer", "transit", "slb",
      "listener_attribute", "voip", "communication", "sip", "rtp"], "network_security_and_connectivity"),
    (["encrypt", "kms", "key", "tls", "ssl", "cipher", "secret", "certificate",
      "rotation", "cmk", "byok", "vault", "bucket", "object_storage",
      "oss", "s3", "blob", "storage", "delete_volume", "delete_disk",
      "backup_policy", "data_exfil", "import_image", "create_image"], "data_protection_and_privacy"),
    (["container", "docker", "kubernetes", "k8s", "pod", "daemonset",
      "kubeconfig", "oke", "aks", "gke", "falco", "admission"], "container_and_kubernetes_security"),
    (["compute", "instance", "vm", "vsi", "ec2", "ecs", "gce", "patch",
      "image", "ami", "launch_template", "metadata", "imds", "ssm",
      "host", "dedicated", "bare_metal", "node", "hypervisor", "auditd",
      "nested_virtualization", "time_sync", "ntp", "modify_time",
      "stop_security_agent", "uninstall_cloudmonitor", "osconfig", "oos"], "infrastructure_security"),
    (["scc", "securitycenter", "sas", "security_advisor", "scanning",
      "vulnerability", "anti_bot", "malware", "anti_malware"], "vulnerability_and_threat_management"),
    (["serverless", "function", "lambda", "cloud_function", "action",
      "schematics", "code_engine"], "application_security"),
]

_DOMAIN_FALLBACK = "configuration_and_change_management"

def infer_domain(rule_id: str) -> str:
    rid_lower = rule_id.lower()
    for keywords, domain in _DOMAIN_PATTERNS:
        if any(k in rid_lower for k in keywords):
            return domain
    return _DOMAIN_FALLBACK

def infer_posture_category(domain: str, rule_type: str) -> str:
    if rule_type == "ciem":
        return "threat_posture"
    mapping = {
        "identity_and_access_management":    "iam_posture",
        "logging_monitoring_and_alerting":   "logging_posture",
        "network_security_and_connectivity": "network_posture",
        "data_protection_and_privacy":       "data_security_posture",
        "container_and_kubernetes_security": "container_posture",
        "infrastructure_security":           "infrastructure_posture",
        "vulnerability_and_threat_management": "threat_posture",
        "application_security":              "application_posture",
        "configuration_and_change_management": "configuration_posture",
    }
    return mapping.get(domain, "configuration_posture")

def infer_subcategory(rule_id: str, rule_type: str) -> str:
    rid = rule_id.lower()
    if rule_type == "ciem":
        if "chain" in rid:     return "attack_chain"
        if "replay" in rid:    return "credential_replay"
        if "brute" in rid or "login_attempt" in rid: return "brute_force"
        if "inactivit" in rid or "dormant" in rid:   return "dormant_identity"
        if "privilege" in rid: return "privilege_escalation"
        if "auditd" in rid or "disable" in rid or "stop_" in rid: return "defense_evasion"
        if "patch" in rid:     return "patch_evasion"
        if "voip" in rid or "communication" in rid:  return "voip_monitoring"
        return "threat_detection"
    # config rules
    if "encrypt" in rid:      return "encryption"
    if "log" in rid or "audit" in rid: return "audit_logging"
    if "mfa" in rid or "auth" in rid:  return "authentication"
    if "access" in rid or "permission" in rid: return "access_control"
    if "network" in rid or "firewall" in rid:  return "network_configuration"
    if "patch" in rid or "scan" in rid:        return "vulnerability_management"
    return "configuration"

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping
# ─────────────────────────────────────────────────────────────────────────────

_MITRE_PATTERNS: list[tuple[list[str], list[str], list[str], int]] = [
    # (keywords, tactics, techniques, base_risk_score)
    (["auditd_kill", "auditd_disable", "auditd_stop", "auditd_modify",
      "auditd_mount", "auditd_alter", "auditd_evasion", "auditd_tamper",
      "stop_security_agent", "uninstall_cloudmonitor", "disable_scan",
      "disable_va", "disable_osconfig", "disable_osconfig_malware",
      "disable_falco", "stop_anti_bot", "sas.audit.disable",
      "security_advisor.audit.disable"],
     ["defense_evasion"], ["T1562.001"], 80),

    (["patch_override", "patch_evasion", "patch_evasion", "patch_override"],
     ["defense_evasion"], ["T1562"], 72),

    (["nested_virtualization"],
     ["defense_evasion"], ["T1564"], 70),

    (["modify_time", "time_sync", "ntp_disable", "timestamp_anomaly"],
     ["defense_evasion"], ["T1562.001"], 68),

    (["critical_event_missing", "critical_gap", "log_integrity_violation",
      "log_export_delete", "backup_policy_delete", "route_delete",
      "log_removal", "audit_rule_deletion", "activity_log_audit"],
     ["defense_evasion"], ["T1562.008"], 82),

    (["replay", "replay_auth", "replay_detection", "replay_token",
      "replay_credential", "replay_sequence"],
     ["credential_access"], ["T1550", "T1212"], 78),

    (["brute_force", "login_attempt_limit", "excessive_failed_logins",
      "signin_failure_series", "authentication_failure_chain",
      "authentication_anomaly"],
     ["credential_access"], ["T1110"], 75),

    (["console_login_inactive", "login_after_inactivity", "signin_after_inactivity",
      "dormant_user", "inactivity_reactivation", "disable_after_reactivation",
      "login_followed_by_disable"],
     ["initial_access", "persistence"], ["T1078", "T1078.004"], 72),

    (["privileged_anomaly", "privileged_job_run", "privilege_reversion",
      "user_access_review_override"],
     ["privilege_escalation"], ["T1548", "T1548.005"], 80),

    (["api_key_abuse", "api_key_activity", "serviceid_to_api_key",
      "management_key_rotation_bypass"],
     ["credential_access", "persistence"], ["T1528", "T1552.005"], 75),

    (["create_image", "import_image", "vpc_activity_log_create_image",
      "vpc.activity_log.create_image", "audit.create_image"],
     ["persistence"], ["T1525"], 73),

    (["delete_volume", "delete_disk", "audit_delete_volume"],
     ["impact"], ["T1485"], 80),

    (["nested_hypervisor", "nested_virtualization"],
     ["defense_evasion"], ["T1564.006"], 70),

    (["voip", "create_meeting", "create_voice_gateway", "create_voip",
      "contactcenter", "communication"],
     ["collection"], ["T1560"], 55),

    (["account_invite", "folder_change", "resourcemanager"],
     ["persistence"], ["T1136", "T1136.003"], 68),

    (["rdp_session", "ssh_session", "instance_console"],
     ["lateral_movement"], ["T1563", "T1021.001"], 70),

    (["periodic_review", "audit_frequency", "log_review"],
     ["defense_evasion"], ["T1562.008"], 65),

    (["create_broadcast", "create_analysis", "execute_template",
      "workspace_action", "workspace_apply"],
     ["execution"], ["T1059", "T1648"], 60),

    (["user_login_profile_reactivate", "audit_user_login_profile_reactivate"],
     ["persistence"], ["T1078", "T1098"], 72),

    (["config_change", "retention_update", "activitytracker"],
     ["defense_evasion"], ["T1562.008"], 65),

    (["chain.log", "chain_log", "evade_malware", "chain_modify_shield",
      "chain_api_key_abuse", "iam.chain"],
     ["defense_evasion", "privilege_escalation"], ["T1562", "T1548"], 82),
]

_MITRE_DEFAULT = (["defense_evasion"], ["T1562"], 60)

def infer_mitre(rule_id: str) -> tuple[list[str], list[str], int]:
    rid_lower = rule_id.lower()
    for keywords, tactics, techniques, score in _MITRE_PATTERNS:
        if any(k in rid_lower for k in keywords):
            return tactics, techniques, score
    return _MITRE_DEFAULT

# ─────────────────────────────────────────────────────────────────────────────
# Log source mapping (CIEM only)
# ─────────────────────────────────────────────────────────────────────────────

LOG_SOURCE_MAP: dict[str, str] = {
    "aws":       "cloudtrail",
    "azure":     "azure_activity_log",
    "gcp":       "gcp_audit_log",
    "alicloud":  "alicloud_actiontrail",
    "ibm":       "ibm_activity_tracker",
    "oci":       "oci_audit_log",
    "oracle":    "oci_audit_log",
    "k8s":       "k8s_audit_log",
}

# ─────────────────────────────────────────────────────────────────────────────
# Severity mapping
# ─────────────────────────────────────────────────────────────────────────────

def infer_severity(row: dict, risk_score: int) -> str:
    """Derive severity from risk score + framework signal."""
    fw = row.get("frameworks", "")
    priority = row.get("priority", "").strip()
    if priority:
        p = priority.lower()
        if p in ("critical", "high"): return p
        if p in ("medium", "low"):    return p
    if risk_score >= 88: return "critical"
    if risk_score >= 75: return "high"
    if risk_score >= 60: return "medium"
    return "low"

# ─────────────────────────────────────────────────────────────────────────────
# Action category (CIEM)
# ─────────────────────────────────────────────────────────────────────────────

def infer_action_category(rule_id: str) -> str:
    rid = rule_id.lower()
    if any(k in rid for k in ["create", "launch", "workspace_apply", "execute"]):
        return "create"
    if any(k in rid for k in ["delete", "remove", "disable", "stop_", "uninstall",
                                "kill", "backup_policy_delete"]):
        return "delete"
    if any(k in rid for k in ["modify", "update", "patch_override", "reactivat",
                                "override", "change", "alter", "tamper"]):
        return "modify"
    if any(k in rid for k in ["audit", "review", "login", "signin", "console_login",
                                "replay", "brute", "failed_login", "inactivit",
                                "dormant", "activity_log", "log_review"]):
        return "audit_activity"
    if any(k in rid for k in ["chain", "escalat", "abuse"]):
        return "privilege_escalation"
    return "audit_activity"

# ─────────────────────────────────────────────────────────────────────────────
# Remediation templates
# ─────────────────────────────────────────────────────────────────────────────

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "defense_evasion": (
        "1. Immediately investigate the principal that performed this action — treat as potentially compromised.\n"
        "2. Restore any disabled/deleted security controls (logging, agents, scanning).\n"
        "3. Review the full session context for lateral movement or data exfiltration following this action.\n"
        "4. Restrict the ability to disable security tools to break-glass roles with MFA enforcement.\n"
        "5. Add SCPs/Organization Policies to prevent non-authorized disablement of security controls."
    ),
    "credential_access": (
        "1. Lock the account or invalidate the session immediately if replay or brute force confirmed.\n"
        "2. Force MFA re-enrollment and rotate all API keys/secrets for the affected principal.\n"
        "3. Review all actions taken by the principal in the surrounding time window.\n"
        "4. Enforce account lockout policies after N failed attempts.\n"
        "5. Enable anomaly detection alerts for repeated authentication failures."
    ),
    "privilege_escalation": (
        "1. Revoke the escalated permissions immediately.\n"
        "2. Audit all policies and roles attached to the principal.\n"
        "3. Review recent resource access with the elevated permissions.\n"
        "4. Enforce Just-in-Time (JIT) access for privileged roles.\n"
        "5. Require manager approval and MFA for policy attachment operations."
    ),
    "initial_access": (
        "1. Disable the dormant/inactive account immediately after investigation.\n"
        "2. Audit all actions taken during the re-activation session.\n"
        "3. Enforce automatic account deactivation after 90 days of inactivity.\n"
        "4. Require MFA and manager approval for account reactivation.\n"
        "5. Alert on first login after extended inactivity periods."
    ),
    "persistence": (
        "1. Remove the unauthorized resource (user, key, image, account) immediately.\n"
        "2. Audit all resources created by the same principal.\n"
        "3. Restrict resource creation to approved provisioning pipelines.\n"
        "4. Add detection for resource creation outside of business hours or from unusual IPs.\n"
        "5. Review SCPs and permission boundaries to limit persistence mechanisms."
    ),
    "impact": (
        "1. Verify the deletion was authorized and check if backups exist.\n"
        "2. Restore data from the most recent backup if deletion was unauthorized.\n"
        "3. Restrict delete operations to break-glass roles with dual approval.\n"
        "4. Enable object-level delete protection (versioning, soft-delete, retention locks).\n"
        "5. Alert immediately on bulk delete operations."
    ),
    "lateral_movement": (
        "1. Terminate the suspicious session immediately.\n"
        "2. Audit all resources accessed during the session.\n"
        "3. Enforce session timeout and MFA for remote access protocols.\n"
        "4. Use jump-hosts/bastion hosts with full session recording.\n"
        "5. Restrict direct instance access to approved principals only."
    ),
    "execution": (
        "1. Terminate the suspicious workload or execution immediately.\n"
        "2. Audit the code/template deployed for malicious payloads.\n"
        "3. Enforce code signing and image verification before deployment.\n"
        "4. Restrict template/workspace execution to approved pipelines.\n"
        "5. Implement mandatory peer review for infrastructure-as-code changes."
    ),
    "collection": (
        "1. Audit the newly created resource and its associated network access rules.\n"
        "2. Verify VoIP/communication resources are authorized and properly scoped.\n"
        "3. Apply least-privilege NSG/security group rules for VoIP ports.\n"
        "4. Monitor for data collection patterns from the resource.\n"
        "5. Ensure communication services are deployed via approved templates only."
    ),
}

def infer_remediation(tactics: list[str]) -> str:
    for t in tactics:
        if t in _REMEDIATION_TEMPLATES:
            return _REMEDIATION_TEMPLATES[t]
    return _REMEDIATION_TEMPLATES["defense_evasion"]

# ─────────────────────────────────────────────────────────────────────────────
# References per compliance framework
# ─────────────────────────────────────────────────────────────────────────────

_MITRE_REF = "https://attack.mitre.org/techniques/{technique}/"
_CSP_REFS: dict[str, dict[str, str]] = {
    "aws":      {"iam": "https://docs.aws.amazon.com/IAM/latest/UserGuide/",
                 "cloudtrail": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"},
    "azure":    {"aad": "https://docs.microsoft.com/azure/active-directory/",
                 "monitor": "https://docs.microsoft.com/azure/azure-monitor/"},
    "gcp":      {"iam": "https://cloud.google.com/iam/docs/",
                 "logging": "https://cloud.google.com/logging/docs/"},
    "alicloud": {"ram": "https://www.alibabacloud.com/help/en/ram/",
                 "actiontrail": "https://www.alibabacloud.com/help/en/actiontrail/"},
    "ibm":      {"iam": "https://cloud.ibm.com/docs/account?topic=account-iamoverview",
                 "activity_tracker": "https://cloud.ibm.com/docs/activity-tracker"},
    "oci":      {"iam": "https://docs.oracle.com/en-us/iaas/Content/Identity/",
                 "audit": "https://docs.oracle.com/en-us/iaas/Content/Audit/"},
    "oracle":   {"iam": "https://docs.oracle.com/en-us/iaas/Content/Identity/",
                 "audit": "https://docs.oracle.com/en-us/iaas/Content/Audit/"},
    "k8s":      {"audit": "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
                 "rbac": "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
}

def build_references(csp: str, service: str, techniques: list[str]) -> list[str]:
    refs = []
    for tech in techniques:
        t = tech.split(".")[0]
        refs.append(_MITRE_REF.format(technique=tech))
    csp_map = _CSP_REFS.get(csp, {})
    for svc_key, url in csp_map.items():
        if svc_key in service.lower():
            refs.append(url)
            break
    if not any(csp_map.get(k, "") in refs for k in csp_map):
        refs.append(list(csp_map.values())[0] if csp_map else
                    f"https://docs.{csp}.com/security/")
    return refs[:3]

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG rule metadata template
# ─────────────────────────────────────────────────────────────────────────────

def _config_references(csp: str, service: str) -> list[str]:
    csp_map = _CSP_REFS.get(csp, {})
    for svc_key, url in csp_map.items():
        if svc_key in service.lower():
            return [url]
    return [list(csp_map.values())[0]] if csp_map else \
           [f"https://docs.{csp}.com/security/{service}"]

def build_config_metadata(row: dict, csp: str, service: str) -> dict:
    rule_id     = row["suggested_rule_id"]
    title_raw   = row.get("sample_title", "").strip()
    comp        = parse_compliance(row.get("frameworks", ""), row.get("compliance_ids", ""))
    domain      = infer_domain(rule_id)
    posture_cat = infer_posture_category(domain, "config")
    subcategory = infer_subcategory(rule_id, "config")

    # Build human title from rule_id if sample_title is missing/short
    parts = rule_id.split(".")
    check_name = parts[-1].replace("_", " ").title() if parts else rule_id
    resource   = parts[2].replace("_", " ").title() if len(parts) > 2 else service
    # Take only the first sentence of sample_title (CSV can have multiple separated by "; ")
    title_clean = title_raw.split(";")[0].strip()[:200] if title_raw else ""
    title = (f"{csp.upper()} {service.upper()}: {check_name}"
             if not title_clean or len(title_clean) < 20
             else title_clean)

    description = (
        f"Validates that {csp} {service} {resource.lower()} has {check_name.lower()} "
        f"configured according to security best practices."
    )
    rationale = (
        f"Proper {check_name.lower()} configuration reduces security risk and ensures "
        f"compliance with {', '.join(list(comp.keys())[:3]) or 'industry standards'}."
    )

    severity_hint = infer_severity(row, 60)

    return {
        "rule_id":         rule_id,
        "service":         service,
        "provider":        csp,
        "check_type":      "resource",
        "severity":        severity_hint,
        "title":           title,
        "description":     description,
        "rationale":       rationale,
        "domain":          domain,
        "subcategory":     subcategory,
        "posture_category": posture_cat,
        "compliance_frameworks": comp,
        "remediation":     (
            f"Review and configure {check_name.lower()} for the {service} {resource.lower()} "
            f"according to {csp.upper()} security best practices and your organisational policy."
        ),
        "references":      _config_references(csp, service),
        "source":          "csv_generated",
        "generated_by":    "step1_build_metadata",
    }

# ─────────────────────────────────────────────────────────────────────────────
# CIEM rule metadata template
# ─────────────────────────────────────────────────────────────────────────────

_CIEM_RESOURCE_MAP: dict[str, str] = {
    "iam": "cloud_iam_principal", "ram": "alicloud_ram_user",
    "aad": "azure_ad_principal", "cloudtrail": "aws_cloudtrail_trail",
    "actiontrail": "alicloud_actiontrail_trail",
    "compute": "cloud_compute_instance", "ec2": "aws_ec2_instance",
    "ecs": "alicloud_ecs_instance", "vm": "azure_vm",
    "gce": "gcp_compute_instance", "vsi": "ibm_vpc_vsi",
    "monitor": "cloud_monitoring_resource",
    "sas": "alicloud_security_center", "oke": "oci_oke_cluster",
    "k8s": "k8s_cluster",
}

def _ciem_resource(csp: str, service: str) -> str:
    for k, v in _CIEM_RESOURCE_MAP.items():
        if k in service.lower():
            return v
    return f"{csp}_{service}_resource"

_THREAT_CAT_FROM_TACTICS: dict[str, str] = {
    "defense_evasion":   "defense_evasion",
    "credential_access": "credential_access",
    "privilege_escalation": "privilege_escalation",
    "initial_access":    "initial_access",
    "persistence":       "persistence",
    "impact":            "impact",
    "lateral_movement":  "lateral_movement",
    "execution":         "execution",
    "collection":        "collection",
}

def build_ciem_metadata(row: dict, csp: str, service: str) -> dict:
    rule_id      = row["suggested_rule_id"]
    title_raw    = row.get("sample_title", "").strip()
    comp         = parse_compliance(row.get("frameworks", ""), row.get("compliance_ids", ""))
    tactics, techniques, risk_score = infer_mitre(rule_id)
    domain       = infer_domain(rule_id)
    posture_cat  = "threat_posture"
    subcategory  = infer_subcategory(rule_id, "ciem")
    action_cat   = infer_action_category(rule_id)
    threat_cat   = _THREAT_CAT_FROM_TACTICS.get(tactics[0], "defense_evasion")
    log_src      = LOG_SOURCE_MAP.get(csp, "cloud_audit_log")
    severity_val = infer_severity(row, risk_score)
    resource_val = _ciem_resource(csp, service)

    parts = rule_id.split(".")
    check_name = parts[-1].replace("_", " ").title() if parts else rule_id

    title_clean = title_raw.split(";")[0].strip()[:200] if title_raw else ""
    title = (f"CIEM: {check_name}"
             if not title_clean or len(title_clean) < 15
             else title_clean)

    description = (
        row.get("review_note", "").strip() or
        row.get("sample_title", "").strip() or
        f"Detects {check_name.lower()} activity in {csp.upper()} {service} audit logs."
    )[:500]

    rationale = (
        f"Monitoring this activity is essential for detecting adversary {tactics[0].replace('_',' ')} "
        f"against {csp.upper()} resources. Unauthorized or unexpected API calls may indicate "
        f"account compromise, privilege escalation, or an active attack chain."
    )

    # Threat tags
    threat_tags: list[str] = []
    for t in techniques:
        threat_tags.append(t)
        threat_tags.append(t.split(".")[0])
    threat_tags += tactics
    threat_tags.append("ciem_detection")
    if "chain" in rule_id: threat_tags.append("attack_chain")
    threat_tags = list(dict.fromkeys(threat_tags))[:8]  # dedupe, cap at 8

    return {
        "rule_id":          rule_id,
        "service":          service,
        "provider":         csp,
        "check_type":       "log",
        "severity":         severity_val,
        "title":            title,
        "description":      description,
        "rationale":        rationale,
        "threat_category":  threat_cat,
        "mitre_tactics":    tactics,
        "mitre_techniques": techniques,
        "risk_score":       risk_score,
        "resource":         resource_val,
        "source":           "csv_generated",
        "is_active":        True,
        "domain":           domain,
        "action_category":  action_cat,
        "log_source_type":  log_src,
        "posture_category": posture_cat,
        "subcategory":      subcategory,
        "threat_tags":      threat_tags,
        "risk_indicators": {
            "actor_type":   "cloud_principal",
            "action_type":  ("write" if action_cat in ("create", "delete", "modify")
                             else "read"),
            "target_type":  "cloud_resource",
            "blast_radius": "account",
            "stealth_risk": ("high" if "evasion" in threat_cat else "medium"),
        },
        "iam_security": {
            "applicable": ("iam" in rule_id or "ram" in rule_id or
                           "privilege" in rule_id or "access" in rule_id),
            "modules": (["access_control"] if "privilege" in rule_id else []),
        },
        "data_security":  {"applicable": False},
        "compliance_frameworks": comp,
        "remediation":    infer_remediation(tactics),
        "references":     build_references(csp, service, techniques),
        "generated_by":   "step1_build_metadata",
        # NOTE: check_config is intentionally OMITTED here — step3 fills it
        # into the full CIEM rule YAML. Metadata files don't carry check_config.
    }

# ─────────────────────────────────────────────────────────────────────────────
# Service normalisation: rule_id part[1] → canonical service directory name
# ─────────────────────────────────────────────────────────────────────────────

_SVC_OVERRIDES: dict[str, str] = {
    # alicloud
    "actiontrail": "actiontrail", "ecs": "compute", "ram": "iam",
    "oos": "compute", "sas": "threat", "securitycenter": "threat",
    "resourcemanager": "iam", "slb": "network", "voicenavigator": "network",
    # aws
    "chime": "network", "cloudtrail": "logging", "ec2": "compute",
    "ssm": "compute",
    # azure
    "aad": "iam", "compute": "compute", "vm": "compute",
    "monitor": "logging", "communication": "network",
    # gcp
    "cloudaudit": "logging", "osconfig": "compute", "logging": "logging",
    "contactcenterinsights": "network",
    # ibm
    "activity_tracker": "logging", "activitytracker": "logging",
    "cloudant": "database", "codeengine": "compute", "functions": "compute",
    "schematics": "compute", "security_advisor": "threat",
    "securityadvisor": "threat", "vpc": "network", "is": "network",
    "watson": "network",
    # k8s
    "apiserver": "logging", "audit": "logging", "container": "compute",
    "falco": "threat", "node": "compute",
    # oci
    "announcements": "network", "compute": "compute",
}

def extract_service(rule_id: str) -> str:
    parts = rule_id.split(".")
    raw = parts[1] if len(parts) > 1 else "unknown"
    return _SVC_OVERRIDES.get(raw, raw)

def norm_csp(csp: str) -> str:
    return "oci" if csp == "oracle" else csp

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    with open(CSV_PATH, newline="") as f:
        rows = list(csv.DictReader(f))

    # Apply filters
    if FILTER_CSP:
        rows = [r for r in rows if norm_csp(r["csp"]) == FILTER_CSP
                or r["csp"] == FILTER_CSP]
    if FILTER_TYPE:
        rows = [r for r in rows if r["rule_type"] == FILTER_TYPE]

    print(f"Processing {len(rows)} rules ...")

    report: dict[str, Any] = {
        "total": len(rows), "written": 0, "skipped": 0,
        "by_csp": defaultdict(int), "by_type": defaultdict(int),
        "errors": [],
    }

    for row in rows:
        rule_id  = row["suggested_rule_id"].strip()
        csp      = norm_csp(row["csp"].strip())
        rule_type = row["rule_type"].strip()
        service  = extract_service(rule_id)

        meta_dir  = RULE_DIR / f"{csp}_rule_metadata" / service
        meta_file = meta_dir / f"{rule_id}.yaml"

        if meta_file.exists() and not OVERWRITE:
            report["skipped"] += 1
            continue

        try:
            if rule_type == "ciem":
                meta = build_ciem_metadata(row, csp, service)
            else:
                meta = build_config_metadata(row, csp, service)
        except Exception as exc:
            report["errors"].append({"rule_id": rule_id, "error": str(exc)})
            continue

        if APPLY:
            meta_dir.mkdir(parents=True, exist_ok=True)
            meta_file.write_text(
                yaml.dump(meta, allow_unicode=True, sort_keys=False,
                          default_flow_style=False),
                encoding="utf-8",
            )

        report["written"] += 1
        report["by_csp"][csp] += 1
        report["by_type"][rule_type] += 1

    # Summary
    print(f"\nDone.")
    print(f"  Written : {report['written']}")
    print(f"  Skipped : {report['skipped']} (already exist)")
    print(f"  Errors  : {len(report['errors'])}")
    print(f"\nBy CSP:")
    for k, v in sorted(report["by_csp"].items()): print(f"  {k}: {v}")
    print(f"\nBy type:")
    for k, v in sorted(report["by_type"].items()): print(f"  {k}: {v}")

    if report["errors"]:
        print(f"\nErrors:")
        for e in report["errors"][:10]:
            print(f"  {e['rule_id']}: {e['error']}")

    # Write report
    report_path = RULE_DIR / "metadata_generation_report.json"
    if APPLY:
        report_path.write_text(
            json.dumps({k: dict(v) if isinstance(v, defaultdict) else v
                        for k, v in report.items()}, indent=2),
            encoding="utf-8",
        )
        print(f"\nReport: {report_path}")

    if not APPLY:
        print("\n*** Pass --apply to write files ***")


if __name__ == "__main__":
    main()
