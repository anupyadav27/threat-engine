#!/usr/bin/env python3
"""
step3_generate_rule_files.py
============================
Phase 3: Generate actual rule YAML files using metadata (step1) + resolution (step2).

CONFIG rules  → append entries to {csp}_rule_check/{service}/checks.yaml
CIEM rules    → write {csp}_rule_ciem/{service}/{rule_id}.yaml  (check_config via DeepSeek)

DeepSeek API: https://api.deepseek.com  model: deepseek-chat
Key: sk-3d7acb8511ad4da18e8b0c89733f472b

Usage:
    python3 catalog/rule/step3_generate_rule_files.py                   # dry-run all
    python3 catalog/rule/step3_generate_rule_files.py --apply           # write all
    python3 catalog/rule/step3_generate_rule_files.py --apply --type config
    python3 catalog/rule/step3_generate_rule_files.py --apply --type ciem --csp aws
    python3 catalog/rule/step3_generate_rule_files.py --apply --overwrite
"""
from __future__ import annotations

import csv
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
CSV_PATH = ROOT / "complaince_csv" / "new_rules_deduplicated.csv"

APPLY      = "--apply"     in sys.argv
OVERWRITE  = "--overwrite" in sys.argv
FILTER_CSP  = None
FILTER_TYPE = None
for i, a in enumerate(sys.argv):
    if a == "--csp"  and i + 1 < len(sys.argv): FILTER_CSP  = sys.argv[i+1].lower()
    if a == "--type" and i + 1 < len(sys.argv): FILTER_TYPE = sys.argv[i+1].lower()

if not APPLY:
    print("*** DRY-RUN — pass --apply to write files ***\n")

# ─────────────────────────────────────────────────────────────────────────────
# Load step1 metadata + step2 resolution
# ─────────────────────────────────────────────────────────────────────────────

def load_metadata(rule_id: str, csp: str, service: str) -> dict:
    svc_dir = RULE_DIR / f"{csp}_rule_metadata" / service
    f = svc_dir / f"{rule_id}.yaml"
    if f.exists():
        return yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    return {}

RES_PATH = RULE_DIR / "discovery_resolution.json"
RESOLUTION: dict = json.loads(RES_PATH.read_text()) if RES_PATH.exists() else {}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def norm_csp(c: str) -> str:
    return "oci" if c == "oracle" else c

def extract_service(rule_id: str) -> str:
    """Mirror step1's service extraction."""
    _SVC_OVERRIDES = {
        "actiontrail":"actiontrail","ecs":"compute","ram":"iam","oos":"compute",
        "sas":"threat","securitycenter":"threat","resourcemanager":"iam",
        "slb":"network","voicenavigator":"network",
        "chime":"network","cloudtrail":"logging","ec2":"compute","ssm":"compute",
        "aad":"iam","compute":"compute","vm":"compute","monitor":"logging",
        "communication":"network",
        "cloudaudit":"logging","osconfig":"compute","logging":"logging",
        "contactcenterinsights":"network",
        "activity_tracker":"logging","activitytracker":"logging",
        "cloudant":"database","codeengine":"compute","functions":"compute",
        "schematics":"compute","security_advisor":"threat","securityadvisor":"threat",
        "vpc":"network","is":"network","watson":"network",
        "apiserver":"logging","audit":"logging","container":"compute",
        "falco":"threat","node":"compute",
        "announcements":"network",
    }
    raw = rule_id.split(".")[1] if "." in rule_id else "unknown"
    return _SVC_OVERRIDES.get(raw, raw)

def severity_upper(s: str) -> str:
    return s.upper() if s else "MEDIUM"

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG rule generation
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────

def build_check_conditions(res: dict, check_name: str) -> dict:
    """Build conditions block from resolution or fallback."""
    var   = res.get("var",   "item.enabled")
    op    = res.get("op",    "is_true")
    value = res.get("value")  # None means no value field needed

    # Encrypted rules often need two conditions
    if "encrypt" in check_name.lower():
        return {"all": [
            {"var": var,             "op": "not_empty", "value": None},
            {"var": "item.kms_key_id","op": "exists",   "value": None},
        ]}

    if value is None:
        return {"var": var, "op": op}
    return {"var": var, "op": op, "value": str(value)}

def generate_config_rules(rows: list[dict]) -> dict[str, dict]:
    """
    Returns: {'{csp}|{service}' → {'header': {...}, 'checks': [...]}}
    """
    groups: dict[str, dict] = {}

    for row in rows:
        rule_id    = row["suggested_rule_id"].strip()
        csp        = norm_csp(row["csp"].strip())
        service    = extract_service(rule_id)
        check_name = rule_id.split(".")[-1]
        meta       = load_metadata(rule_id, csp, service)
        severity   = severity_upper(meta.get("severity", "medium"))

        res = RESOLUTION.get(rule_id, {})
        status = res.get("status", "no_resolution")

        if status == "resolved":
            for_each   = res["for_each"]
            conditions = build_check_conditions(res, check_name)
            stub_note  = None
        else:
            # Stub: mark clearly, rule is real but needs discovery wiring
            for_each   = f"# STUB: {csp}.{rule_id.split('.')[1]}.list_resources"
            conditions = {"var": "item.enabled", "op": "is_true"}
            stub_note  = f"NEEDS_DISCOVERY: {res.get('raw_svc', rule_id.split('.')[1])}"

        check_entry: dict[str, Any] = {
            "rule_id":  rule_id,
            "for_each": for_each,
            "severity": severity,
            "conditions": conditions,
        }
        if stub_note:
            check_entry["_stub"] = stub_note

        key = f"{csp}|{service}"
        if key not in groups:
            groups[key] = {
                "header": {"version": "1.0", "provider": csp, "service": service},
                "checks": [],
            }
        groups[key]["checks"].append(check_entry)

    return groups


def write_config_rules(groups: dict[str, dict]) -> tuple[int, int]:
    written = skipped = 0
    for key, group in groups.items():
        csp, service = key.split("|", 1)
        svc_dir  = RULE_DIR / f"{csp}_rule_check" / service
        chk_file = svc_dir / "checks.yaml"

        # Load existing checks to avoid duplicates
        existing_ids: set[str] = set()
        existing_data: dict = {}
        if chk_file.exists():
            try:
                existing_data = yaml.safe_load(chk_file.read_text(encoding="utf-8")) or {}
                for c in existing_data.get("checks", []):
                    if isinstance(c, dict):
                        existing_ids.add(c.get("rule_id", ""))
            except Exception:
                existing_data = {}

        new_checks = [c for c in group["checks"]
                      if OVERWRITE or c["rule_id"] not in existing_ids]
        if not new_checks:
            skipped += len(group["checks"])
            continue

        if APPLY:
            svc_dir.mkdir(parents=True, exist_ok=True)
            out_checks = existing_data.get("checks", []) + new_checks
            out = {**group["header"], "checks": out_checks}
            chk_file.write_text(
                yaml.dump(out, allow_unicode=True, sort_keys=False,
                          default_flow_style=False),
                encoding="utf-8",
            )

        written += len(new_checks)
        skipped += len(group["checks"]) - len(new_checks)

    return written, skipped


# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  CIEM rule generation — check_config via DeepSeek
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────

DEEPSEEK_KEY = "sk-3d7acb8511ad4da18e8b0c89733f472b"
DEEPSEEK_URL = "https://api.deepseek.com"

# ── Log source types per CSP
LOG_SOURCE = {
    "aws":      "cloudtrail",
    "azure":    "azure_activity_log",
    "gcp":      "gcp_audit_log",
    "alicloud": "alicloud_actiontrail",
    "ibm":      "ibm_activity_tracker",
    "oci":      "oci_audit_log",
    "k8s":      "k8s_audit",
}

# ── Service code mapping: rule_id_part[1] → log service code used in check_config
_SERVICE_CODE: dict[str, dict[str, str]] = {
    "alicloud": {
        "actiontrail": "actiontrail", "ecs": "ecs", "ram": "ram",
        "oos": "oos", "sas": "sas", "securitycenter": "sas",
        "slb": "slb", "voicenavigator": "voicenavigator",
        "resourcemanager": "resourcemanager",
    },
    "aws": {
        "chime": "chime", "cloudtrail": "cloudtrail",
        "ec2": "ec2", "iam": "iam", "ssm": "ssm",
    },
    "azure": {
        "aad":           "Microsoft.AAD",
        "compute":       "Microsoft.Compute",
        "vm":            "Microsoft.Compute",
        "monitor":       "microsoft.insights",
        "communication": "Microsoft.Communication",
    },
    "gcp": {
        "cloudaudit":            "cloudresourcemanager.googleapis.com",
        "compute":               "compute.googleapis.com",
        "iam":                   "iam.googleapis.com",
        "logging":               "logging.googleapis.com",
        "osconfig":              "osconfig.googleapis.com",
        "contactcenterinsights": "contactcenterinsights.googleapis.com",
    },
    "ibm": {
        "activity_tracker": "logdna", "activitytracker": "logdna",
        "cloudant": "cloudantnosqldb", "codeengine": "codeengine",
        "functions": "functions", "iam": "iam-am",
        "is": "is.instance", "resource": "resource-controller",
        "schematics": "schematics", "security_advisor": "security-advisor",
        "securityadvisor": "security-advisor", "vpc": "is.vpc",
        "watson": "pm-20",
    },
    "k8s": {
        "apiserver": "k8s_apiserver", "audit": "k8s_audit",
        "container": "k8s_audit",    "falco": "falco",
        "node": "k8s_audit",
    },
    "oci": {
        "announcements": "com.oraclecloud.announcements",
        "audit":         "com.oraclecloud.audit",
        "compute":       "com.oraclecloud.computemanagement",
    },
}

def get_service_code(csp: str, raw_svc: str) -> str:
    return _SERVICE_CODE.get(csp, {}).get(raw_svc, raw_svc)

# ── Rule pattern classification
def rule_pattern(rule_id: str) -> str:
    parts = rule_id.lower().split(".")
    if len(parts) > 2:
        p = parts[2]
        if p == "chain":           return "chain"
        if p == "activity_log":    return "activity_log"
        if p == "audit":           return "audit"
    return "audit"

# ─────────────────────────────────────────────────────────────────────────────
# Fallback templates (used when DeepSeek is unavailable or response is invalid)
# ─────────────────────────────────────────────────────────────────────────────

def _source_condition(csp: str) -> dict:
    return {"field": "source_type", "op": "equals", "value": LOG_SOURCE[csp]}

def _svc_condition(csp: str, raw_svc: str) -> Optional[dict]:
    """Return service condition or None (Azure uses operation only)."""
    if csp == "azure":
        return None
    code = get_service_code(csp, raw_svc)
    return {"field": "service", "op": "equals", "value": code}

# ── infer operations from rule_id suffix
_OP_HINTS: dict[str, dict[str, list[str]]] = {
    "alicloud": {
        "auditd_kill":         ["RunCommand", "InvokeCommand"],
        "modify_time_service": ["ModifyInstanceAttribute", "StopLogging"],
        "create_image":        ["CreateImage", "CreateCustomImage"],
        "enable_nested_virtualization": ["ModifyInstanceSpec"],
        "patch_override":      ["RunCommand", "ModifyPatchStatus"],
        "stop_security_agent": ["CloseAgent", "StopAgent"],
        "uninstall_cloudmonitor": ["UninstallCloudMonitor", "DeleteApplication"],
        "execute_template":    ["ExecuteTemplate", "StartExecution"],
        "console_login_inactive_user": ["ConsoleLogin"],
        "login_attempt_limit": ["ConsoleLogin", "GetLoginProfile"],
        "replay_detection":    ["AssumeRole", "SwitchRole", "GetSessionToken"],
        "privileged_anomaly":  ["CreatePolicy", "AttachPolicy", "AssumeRole"],
        "user_login_profile_reactivate": ["CreateLoginProfile", "UpdateLoginProfile"],
        "folder_change":       ["MoveResourceGroup", "CreateFolder", "UpdateFolder"],
        "backup_policy_delete":["DeleteBackupPolicy", "DeleteTrail"],
        "disable":             ["DisableService", "StopLogging"],
        "stop_anti_bot":       ["StopInstance", "DeletePolicy"],
        "disable_scan":        ["DisableTask", "StopTask"],
        "listener_attribute_modify": ["SetLoadBalancerHTTPSListenerAttribute", "ModifyListenerAttribute"],
        "create_instance":     ["CreateInstance", "CreateNamespace"],
        "activity_log_review_anomaly": ["DescribeTrails", "GetTrailStatus"],
        "critical_gap":        ["StopLogging", "DeleteTrail", "GetTrailStatus"],
    },
    "aws": {
        "critical_event_missing": ["StopLogging", "DeleteTrail", "PutEventSelectors"],
        "periodic_review":     ["LookupEvents", "DescribeTrails"],
        "replay_auth_anomaly": ["GetSessionToken", "AssumeRole", "AssumeRoleWithWebIdentity"],
        "auditd_disable":      ["SendCommand", "StartSession"],
        "delete_volume":       ["DeleteVolume", "CreateSnapshot"],
        "import_image":        ["ImportImage", "RunInstances"],
        "modify_time_sync":    ["ModifyInstanceAttribute", "StopLogging"],
        "console_login_followed_by_disable": ["ConsoleLogin", "DeactivateMFADevice"],
        "replay_attempt":      ["GetSessionToken", "AssumeRole", "AssumeRoleWithSAML"],
        "user_access_review_override": ["AttachUserPolicy", "PutUserPolicy"],
        "user_inactivity_reactivation": ["ConsoleLogin", "CreateLoginProfile"],
        "chain_auditd_tamper": ["SendCommand", "StartSession"],
        "chain_patch_evasion": ["SendCommand", "ModifyInstanceAttribute"],
        "create_meeting":      ["CreateMeeting", "CreateVpcEndpoint"],
        "chain_replay_auth_anomaly": ["GetSessionToken", "AssumeRole"],
    },
    "azure": {
        "replay_token":       ["microsoft.aad/users/invalidateAllRefreshTokens/action",
                               "microsoft.aad/signIn/read"],
        "signin_after_inactivity": ["microsoft.aad/signIn/read",
                                    "microsoft.aad/users/enable/action"],
        "signin_failure_series": ["microsoft.aad/signIn/read"],
        "create_voip_resource": ["Microsoft.Communication/CommunicationServices/write"],
        "rdp_session_anomaly": ["microsoft.aad/conditionalAccess/policies/write",
                                "Microsoft.Compute/virtualMachines/extensions/write"],
        "nested_hypervisor_enable": ["Microsoft.Compute/virtualMachines/write"],
        "timestamp_anomaly":  ["microsoft.operationalinsights/workspaces/delete",
                               "microsoft.insights/activityLogAlerts/delete"],
        "brute_force_pattern": ["microsoft.aad/signIn/read"],
        "auditd_modify":      ["Microsoft.Compute/virtualMachines/extensions/write",
                               "Microsoft.Automation/automationAccounts/runbooks/write"],
        "modify_time_config": ["Microsoft.Compute/virtualMachines/write",
                               "microsoft.insights/logProfiles/delete"],
        "patch_override":     ["Microsoft.Compute/virtualMachines/write",
                               "Microsoft.Automation/automationAccounts/runbooks/publish/action"],
    },
    "gcp": {
        "authentication_anomaly": ["google.iam.admin.v1.ListServiceAccountKeys",
                                   "google.login.LoginService.loginFailure"],
        "auditd_alter":      ["compute.instances.setMetadata",
                              "osconfig.patchDeployments.patch"],
        "create_image":      ["compute.images.insert", "osconfig.patchJobs.execute"],
        "delete_disk":       ["compute.disks.delete", "compute.snapshots.insert"],
        "disable_osconfig_malware": ["osconfig.guestPolicies.delete",
                                     "iam.roles.update"],
        "set_nested_virtualization": ["compute.instances.insert",
                                      "compute.instances.setMetadata"],
        "instance_creation_without_integrity": ["compute.instances.insert"],
        "patch_override":    ["osconfig.patchDeployments.patch",
                              "compute.instances.setMetadata"],
        "ssh_session_chain": ["google.login.LoginService.loginSuccess",
                              "compute.instances.setMetadata"],
        "create_analysis":   ["compute.firewalls.insert",
                              "contactcenterinsights.conversations.analyze"],
        "disable_2sv":       ["google.login.LoginService.logout",
                              "compute.instances.setMetadata"],
        "replay_detection":  ["iam.serviceAccountKeys.create",
                              "google.iam.admin.v1.GetServiceAccount"],
        "dormant_user_console_access": ["google.login.LoginService.loginSuccess"],
        "audit_frequency":   ["logging.sinks.delete", "iam.roles.update"],
        "patch_execution":   ["compute.instances.insert",
                              "osconfig.patchJobs.execute"],
        "auditd_evasion":    ["compute.instances.setMetadata",
                              "osconfig.patchDeployments.delete"],
    },
    "ibm": {
        "audit_rule_deletion":     ["security-group.delete", "network-acl.delete"],
        "log_integrity_violation": ["logdna.archive.delete",
                                    "activity-tracker.events.delete"],
        "replay_sequence":         ["iam-identity.token.create",
                                    "iam-am.credentials.exchange"],
        "config_change":           ["security-advisor.findings.create",
                                    "logdna.config.update"],
        "log_export_delete":       ["logdna.export.create", "logdna.archive.delete"],
        "retention_update":        ["logdna.retention.update",
                                    "logdna.config.update"],
        "chain_log_export_delete": ["security-advisor.findings.note",
                                    "logdna.archive.delete"],
        "audit_route_delete":      ["logdna.route.delete",
                                    "cloudantnosqldb.log-config.update"],
        "chain_log_removal":       ["logdna.archive.delete",
                                    "logdna.export.create"],
        "privileged_job_run":      ["codeengine.job.create",
                                    "kubernetes.pods.create"],
        "create_action":           ["functions.action.create",
                                    "functions.action.update"],
        "account_invite":          ["iam-am.account.invite",
                                    "iam-identity.apikey.create"],
        "api_key_activity":        ["iam-identity.apikey.login",
                                    "iam-identity.apikey.use"],
        "excessive_failed_logins": ["iam-identity.user.login"],
        "login_after_inactivity":  ["iam-identity.user.login",
                                    "iam-am.user.enable"],
        "replay_auth":             ["iam-identity.token.create",
                                    "iam-am.credentials.exchange"],
        "serviceid_to_api_key":    ["iam-identity.serviceid.update",
                                    "iam-identity.apikey.create"],
        "disable_after_reactivation": ["iam-identity.user.login",
                                       "iam-am.user.disable"],
        "serviceid_privilege_reversion": ["iam-am.policy.create",
                                          "iam-am.accessgroup.update"],
        "chain_api_key_abuse":     ["security-advisor.service.disable",
                                    "iam-identity.apikey.create"],
        "evade_malware_monitoring": ["is.security-group.log-config.delete",
                                     "iam-am.policy.update"],
        "chain_modify_shield_rules": ["is.security-group.log-config.delete",
                                      "iam-am.policy.delete"],
        "virtual_server_login":    ["iam-identity.apikey.login",
                                    "is.instance.console.start"],
        "audit_delete_volume":     ["is.volume.delete", "is.bucket.delete"],
        "vpc_audit_instance_ssh":  ["iam-identity.apikey.create",
                                    "is.instance.console.start"],
        "management_key_rotation_bypass": ["iam-identity.serviceid.update",
                                           "iam-identity.apikey.create"],
        "workspace_action":        ["schematics.workspace.action",
                                    "is.image.create"],
        "workspace_apply":         ["is.instance.create",
                                    "schematics.workspace.apply"],
        "workspace_variable_modify": ["schematics.workspace.update",
                                      "is.security-group.rule-update"],
        "chain_auditd_tamper":     ["is.instance.delete",
                                    "schematics.workspace.apply"],
        "chain_patch_evasion":     ["is.instance.update",
                                    "schematics.workspace.apply"],
        "disable_va":              ["scc.task.disable",
                                    "is.security-group.rule-update"],
        "security_advisor_audit_disable": ["security-advisor.service.disable",
                                           "iam-identity.apikey.create"],
        "note_creation":           ["security-advisor.findings.create",
                                    "logdna.config.update"],
        "auditd_removal":          ["is.instance.delete",
                                    "schematics.workspace.apply"],
        "vpc_activity_log_create_image": ["is.image.create",
                                          "schematics.workspace.apply"],
        "instance_console_activity": ["iam-am.policy.delete",
                                      "is.instance.console.start"],
        "vpc_audit_patch_override":  ["is.instance.update",
                                      "schematics.workspace.apply"],
        "vpc_chain_nested_virtualization_bypass": ["is.instance.update",
                                                   "is.instance.create"],
        "vpc_chain_profile_template_modification": ["is.instance.update",
                                                    "is.instance.create"],
        "watson_audit_create_voice_gateway": ["is.security-group.rule-update",
                                              "pm-20.deployment.create"],
    },
    "k8s": {
        "authentication_failure_chain": [],  # handled specially
        "replay_credential_use":        [],  # handled specially
        "auditd_mount_tamper":          [],  # handled specially
        "falco_audit_disable":          [],  # handled specially
        "node_chain_time_ntp_disable":  [],  # handled specially
    },
    "oci": {
        "create_broadcast":             ["com.oraclecloud.announcements.CreateBroadcast",
                                         "com.oraclecloud.core.UpdateSecurityList"],
        "auth_replay_pattern":          ["com.oraclecloud.identitycontrolplane.AssumeRole",
                                         "com.oraclecloud.audit.GetAuditEvents"],
        "auditd_stop":                  ["com.oraclecloud.computemanagement.StopInstance",
                                         "com.oraclecloud.osmanagement.RunInstallPackagesOnManagedInstance"],
        "update_instance":              ["com.oraclecloud.computemanagement.UpdateInstance"],
        "disable_scanning_agent":       ["com.oraclecloud.vulnerabilityscanning.RemoveTarget",
                                         "com.oraclecloud.computemanagement.DetachPlugin"],
        "launch_instance_without_trusted_platform": [
                                         "com.oraclecloud.computemanagement.LaunchInstance"],
        "nested_virtualization_flag":   ["com.oraclecloud.computemanagement.LaunchInstance",
                                         "com.oraclecloud.computemanagement.UpdateInstance"],
        "patch_override":               ["com.oraclecloud.computemanagement.UpdateInstance",
                                         "com.oraclecloud.osmanagement.ManageModuleStreamProfileOnManagedInstance"],
        "chain_remove_agent":           ["com.oraclecloud.vulnerabilityscanning.RemoveTarget",
                                         "com.oraclecloud.computemanagement.DetachPlugin"],
    },
}

def lookup_op_hint(csp: str, rule_id: str) -> list[str]:
    """Find operation hints from the _OP_HINTS table using rule suffix."""
    rid_lower  = rule_id.lower()
    csp_hints  = _OP_HINTS.get(csp, {})
    # Try progressively more specific suffix matches
    parts = rid_lower.split(".")
    # Try full suffix, then last 2, then last 1 token
    candidates = [
        ".".join(parts[2:]),   # e.g. "audit.create_image"
        parts[-1],             # e.g. "create_image"
        parts[-2] + "_" + parts[-1],  # e.g. "audit_create_image"
    ]
    for cand in candidates:
        for key, ops in csp_hints.items():
            if key in cand or cand in key:
                return ops
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Template-based check_config builders (no AI)
# ─────────────────────────────────────────────────────────────────────────────

def _cond_block(csp: str, raw_svc: str, ops: list[str]) -> dict:
    """Build a single-event conditions block."""
    if csp == "azure":
        # Azure: operation only, no source_type/service
        if len(ops) == 1:
            return {"all": [{"field": "operation", "op": "equals", "value": ops[0]}]}
        return {"all": [{"field": "operation", "op": "in", "value": ops}]}

    if csp in ("k8s", "ibm") and raw_svc in ("apiserver", "audit", "container", "node", "falco"):
        return _k8s_ibm_cond(csp, raw_svc, ops)

    all_conds: list[dict] = [_source_condition(csp)]
    svc_cond = _svc_condition(csp, raw_svc)
    if svc_cond:
        all_conds.append(svc_cond)
    if len(ops) == 1:
        all_conds.append({"field": "operation", "op": "equals", "value": ops[0]})
    elif ops:
        all_conds.append({"field": "operation", "op": "in", "value": ops})
    return {"all": all_conds}

def _k8s_ibm_cond(csp: str, raw_svc: str, ops: list[str]) -> dict:
    """Build K8s/IBM K8s audit condition block."""
    if csp == "k8s":
        # K8s uses verb + resource instead of operation
        resource_map = {
            "apiserver": "pods", "container": "pods",
            "falco": "pods", "node": "nodes", "audit": "pods",
        }
        verb = "create"
        resource = resource_map.get(raw_svc, "pods")
        return {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": resource},
            {"field": "verb",        "op": "in",     "value": ["create","update","delete"]},
        ]}
    # IBM K8s
    return {"all": [
        {"field": "source_type", "op": "equals", "value": "ibm_activity_tracker"},
        {"field": "action",      "op": "in",     "value": ops or ["iam-identity.user.login"]},
    ]}

def build_single_event_config(csp: str, raw_svc: str, ops: list[str]) -> dict:
    return {
        "conditions": _cond_block(csp, raw_svc, ops),
        "type": "log",
    }

def build_chain_config(csp: str, raw_svc: str, ops: list[str]) -> dict:
    """Build a 2-event sequence check_config."""
    if len(ops) < 2:
        ops = ops + (["UnknownFollowUpOperation"] if ops else
                     ["TriggerOperation", "FollowUpOperation"])
    event1_ops = [ops[0]]
    event2_ops = ops[1:]
    return {
        "events": [
            {"conditions": _cond_block(csp, raw_svc, event1_ops)},
            {"conditions": _cond_block(csp, raw_svc, event2_ops)},
        ],
        "type": "sequence",
        "window_seconds": 600,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DeepSeek enrichment for rules where op hints are missing
# ─────────────────────────────────────────────────────────────────────────────

def _deepseek_enrich(batch: list[dict]) -> dict[str, list[str]]:
    """
    Call DeepSeek for a batch of rules needing operation names.
    Returns: {rule_id → [op1, op2, ...]}
    """
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        return {}

    sys_prompt = (
        "You are a cloud security engineer. "
        "For each rule, return the specific cloud API operation names "
        "that should be monitored in audit logs. "
        "Use the exact API operation format for each CSP: "
        "AWS CloudTrail: CamelCase (e.g. ConsoleLogin, AssumeRole); "
        "AliCloud ActionTrail: CamelCase (e.g. CreateUser, DeleteTrail); "
        "GCP Audit Log: reverse-domain.method (e.g. compute.instances.insert); "
        "Azure Activity Log: Microsoft.Resource/type/action format; "
        "IBM Activity Tracker: service.resource.action format (e.g. iam-identity.user.login); "
        "OCI Audit: com.oraclecloud.service.Operation format; "
        "K8s Audit: use verb (create/update/delete) and resource (pods/nodes/configmaps). "
        "Return JSON array: [{\"rule_id\":\"...\",\"operations\":[\"Op1\",\"Op2\"]}]. "
        "2-4 operations per rule. Chain rules need a trigger op first, then follow-up ops."
    )

    user_lines = []
    for r in batch:
        user_lines.append(
            f"rule_id={r['rule_id']} csp={r['csp']} "
            f"service={r['raw_svc']} pattern={r['pattern']} "
            f"description: {r['description']}"
        )
    user_prompt = "Generate operations for:\n" + "\n".join(user_lines)

    payload = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 1200,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{DEEPSEEK_URL}/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {DEEPSEEK_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            body   = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
    except Exception as exc:
        print(f"  [DeepSeek error] {exc}")
        return {}

    # Extract JSON from response (may be wrapped in markdown)
    content = re.sub(r"^```(?:json)?\s*", "", content.strip())
    content = re.sub(r"\s*```$", "", content.strip())
    try:
        items = json.loads(content)
        return {item["rule_id"]: item.get("operations", []) for item in items
                if isinstance(item, dict) and "rule_id" in item}
    except Exception as exc:
        print(f"  [DeepSeek parse error] {exc}\n  Raw: {content[:200]}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Full CIEM YAML builder
# ─────────────────────────────────────────────────────────────────────────────

def build_full_ciem_yaml(meta: dict, check_config: dict) -> dict:
    """Merge metadata + check_config into a complete CIEM rule YAML."""
    out = {
        "rule_id":          meta.get("rule_id"),
        "service":          meta.get("service"),
        "provider":         meta.get("provider"),
        "check_type":       "log",
        "severity":         meta.get("severity", "medium"),
        "title":            meta.get("title", ""),
        "description":      meta.get("description", ""),
        "rationale":        meta.get("rationale", ""),
        "threat_category":  meta.get("threat_category", "defense_evasion"),
        "mitre_tactics":    meta.get("mitre_tactics", []),
        "mitre_techniques": meta.get("mitre_techniques", []),
        "risk_score":       meta.get("risk_score", 60),
        "resource":         meta.get("resource", "cloud_resource"),
        "source":           "csv_generated",
        "is_active":        True,
        "domain":           meta.get("domain", "configuration_and_change_management"),
        "action_category":  meta.get("action_category", "audit_activity"),
        "log_source_type":  meta.get("log_source_type",
                                     LOG_SOURCE.get(meta.get("provider",""), "cloud_audit_log")),
        "posture_category": "threat_posture",
        "threat_tags":      meta.get("threat_tags", []),
        "risk_indicators":  meta.get("risk_indicators", {}),
        "iam_security":     meta.get("iam_security", {"applicable": False, "modules": []}),
        "data_security":    {"applicable": False},
        "compliance_frameworks": meta.get("compliance_frameworks", {}),
        "remediation":      meta.get("remediation", ""),
        "references":       meta.get("references", []),
        "check_config":     {**check_config, "version": "1.0"},
    }
    return out


def generate_ciem_rules(rows: list[dict]) -> list[tuple[Path, dict]]:
    """
    Returns list of (output_path, yaml_dict) for each CIEM rule.
    Calls DeepSeek in batches for rules without operation hints.
    """
    results: list[tuple[Path, dict]] = []

    # First pass: classify each rule
    need_deepseek: list[dict] = []
    ready: list[tuple[str, str, str, str, list[str]]] = []  # (rule_id,csp,svc,pattern,ops)

    for row in rows:
        rule_id  = row["suggested_rule_id"].strip()
        csp      = norm_csp(row["csp"].strip())
        raw_svc  = rule_id.split(".")[1] if "." in rule_id else "unknown"
        service  = extract_service(rule_id)
        pattern  = rule_pattern(rule_id)
        desc     = (row.get("review_note") or row.get("sample_title") or "").strip()[:200]
        ops      = lookup_op_hint(csp, rule_id)

        if ops:
            ready.append((rule_id, csp, raw_svc, service, pattern, ops))
        else:
            need_deepseek.append({
                "rule_id": rule_id, "csp": csp, "raw_svc": raw_svc,
                "service": service, "pattern": pattern, "description": desc,
            })

    print(f"  CIEM: {len(ready)} have op hints, {len(need_deepseek)} need DeepSeek")

    # DeepSeek batches (10 at a time)
    deepseek_ops: dict[str, list[str]] = {}
    if need_deepseek:
        batch_size = 10
        batches = [need_deepseek[i:i+batch_size]
                   for i in range(0, len(need_deepseek), batch_size)]
        print(f"  Calling DeepSeek in {len(batches)} batches ...")
        for idx, batch in enumerate(batches):
            print(f"    Batch {idx+1}/{len(batches)} ({len(batch)} rules) ...", end=" ", flush=True)
            result = _deepseek_enrich(batch)
            deepseek_ops.update(result)
            print(f"got {len(result)} results")
            if idx < len(batches) - 1:
                time.sleep(1)  # brief pause between batches

        # Merge DeepSeek results back
        for item in need_deepseek:
            ops = deepseek_ops.get(item["rule_id"], [])
            ready.append((
                item["rule_id"], item["csp"], item["raw_svc"],
                item["service"], item["pattern"], ops
            ))

    # Build YAML for every rule
    for rule_id, csp, raw_svc, service, pattern, ops in ready:
        meta = load_metadata(rule_id, csp, service)
        if not meta:
            # Re-derive from row (shouldn't happen since step1 ran first)
            meta = {"rule_id": rule_id, "provider": csp, "service": service}

        if not ops:
            # Ultimate fallback
            fallback_op = f"{raw_svc.capitalize()}Operation"
            ops = [fallback_op]

        if pattern == "chain":
            check_config = build_chain_config(csp, raw_svc, ops)
        else:
            check_config = build_single_event_config(csp, raw_svc, ops)

        out_dir  = RULE_DIR / f"{csp}_rule_ciem" / service
        out_file = out_dir / f"{rule_id}.yaml"
        full     = build_full_ciem_yaml(meta, check_config)
        results.append((out_file, full))

    return results


def write_ciem_rules(items: list[tuple[Path, dict]]) -> tuple[int, int]:
    written = skipped = 0
    for out_file, data in items:
        if out_file.exists() and not OVERWRITE:
            skipped += 1
            continue
        if APPLY:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(
                yaml.dump(data, allow_unicode=True, sort_keys=False,
                          default_flow_style=False),
                encoding="utf-8",
            )
        written += 1
    return written, skipped


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    with open(CSV_PATH, newline="") as f:
        all_rows = list(csv.DictReader(f))

    if FILTER_CSP:
        all_rows = [r for r in all_rows
                    if norm_csp(r["csp"]) == FILTER_CSP or r["csp"] == FILTER_CSP]
    if FILTER_TYPE:
        all_rows = [r for r in all_rows if r["rule_type"] == FILTER_TYPE]

    config_rows = [r for r in all_rows if r["rule_type"] == "config"]
    ciem_rows   = [r for r in all_rows if r["rule_type"] == "ciem"]

    total_written = total_skipped = 0

    # ── Config rules
    if not FILTER_TYPE or FILTER_TYPE == "config":
        print(f"Processing {len(config_rows)} CONFIG rules ...")
        groups   = generate_config_rules(config_rows)
        w, s     = write_config_rules(groups)
        total_written += w
        total_skipped += s
        print(f"  Config → written: {w}, skipped: {s}")

    # ── CIEM rules
    if not FILTER_TYPE or FILTER_TYPE == "ciem":
        print(f"\nProcessing {len(ciem_rows)} CIEM rules ...")
        items    = generate_ciem_rules(ciem_rows)
        w, s     = write_ciem_rules(items)
        total_written += w
        total_skipped += s
        print(f"  CIEM  → written: {w}, skipped: {s}")

    print(f"\nTotal written: {total_written}")
    print(f"Total skipped: {total_skipped}")
    if not APPLY:
        print("\n*** Pass --apply to write files ***")


if __name__ == "__main__":
    main()
