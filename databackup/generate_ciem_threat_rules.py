#!/usr/bin/env python3
"""
CIEM Log Threat Detection Rule Generator — Azure / GCP / OCI / IBM

Generates INSERT SQL for threat-detection log rules covering:
  network, execute, threat, reconnaissance, privilege_escalation,
  authentication, exfiltration, brute_force, c2, malware, cryptomining

Parser → log_events field mapping (relevant for threat rules):
  Azure Activity  — service=lowercased ARM provider, operation=full ARM op, outcome=success/failure
  Azure NSG Flow  — source_type=azure_nsg_flow, flow_action=A/D, dst_port=integer
  Azure AKS Audit — source_type=azure_aks_audit, operation=verb/resource
  Azure Defender  — source_type=azure_defender, severity=Critical/High, operation=alert_type
  GCP Audit       — service=full.googleapis.com, operation=full methodName, outcome=success/failure
  GCP VPC Flow    — source_type=gcp_vpc_flow, flow_action=ALLOWED/DENIED, dst_port=integer
  GCP GKE Audit   — source_type=gcp_gke_audit, operation=verb/resource
  GCP SCC         — source_type=gcp_scc, severity=CRITICAL/HIGH, operation=category
  OCI Audit       — service=com.oraclecloud.*, operation=PascalCase, outcome=success/failure
  OCI VCN Flow    — source_type=oci_vcn_flow, flow_action=ACCEPT/REJECT, dst_port=integer
  OCI CloudGuard  — source_type=oci_cloudguard, severity=CRITICAL/HIGH, operation=event_type
  IBM Activity    — service=first_seg_underscore, operation=full CADF action, outcome=success/failure
  IBM VPC Flow    — source_type=ibm_vpc_flow, flow_action=ACCEPT/REJECT, dst_port=integer

Run: python generate_ciem_threat_rules.py
"""

import json
import os
from typing import List, Tuple


def sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _cfg(conds: list) -> str:
    return sql_str(json.dumps({"conditions": {"all": conds}}, separators=(',', ':')))


# ---------------------------------------------------------------------------
# Config builders per source type
# ---------------------------------------------------------------------------

def azure_activity_cfg(arm_op: str = None, outcome: str = None,
                        op_contains: str = None, service: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "azure_activity"}]
    if outcome:
        conds.append({"op": "equals", "field": "outcome", "value": outcome})
    if service:
        conds.append({"op": "equals", "field": "service", "value": service})
    if arm_op:
        conds.append({"op": "equals", "field": "operation", "value": arm_op})
    if op_contains:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def azure_nsg_cfg(dst_port=None, flow_action=None, dst_ports=None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "azure_nsg_flow"}]
    if flow_action:
        conds.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None:
        conds.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports:
        conds.append({"op": "in", "field": "network.dst_port",
                       "value": [str(p) for p in dst_ports]})
    return _cfg(conds)


def azure_aks_cfg(operation: str) -> str:
    return _cfg([
        {"op": "equals", "field": "source_type", "value": "azure_aks_audit"},
        {"op": "contains", "field": "operation", "value": operation},
    ])


def azure_defender_cfg(severity: str = None, op_contains: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "azure_defender"}]
    if severity:
        conds.append({"op": "equals", "field": "severity", "value": severity})
    if op_contains:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def gcp_audit_cfg(service_uri: str = None, op_contains: str = None,
                   outcome: str = None, operation: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "gcp_audit"}]
    if outcome:
        conds.append({"op": "equals", "field": "outcome", "value": outcome})
    if service_uri:
        conds.append({"op": "equals", "field": "service", "value": service_uri})
    if operation:
        conds.append({"op": "contains", "field": "operation", "value": operation})
    if op_contains and not operation:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def gcp_flow_cfg(dst_port=None, flow_action=None, dst_ports=None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "gcp_vpc_flow"}]
    if flow_action:
        conds.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None:
        conds.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports:
        conds.append({"op": "in", "field": "network.dst_port",
                       "value": [str(p) for p in dst_ports]})
    return _cfg(conds)


def gcp_gke_cfg(operation: str) -> str:
    return _cfg([
        {"op": "equals", "field": "source_type", "value": "gcp_gke_audit"},
        {"op": "contains", "field": "operation", "value": operation},
    ])


def gcp_scc_cfg(severity: str = None, op_contains: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "gcp_scc"}]
    if severity:
        conds.append({"op": "equals", "field": "severity", "value": severity})
    if op_contains:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def oci_audit_cfg(cadf_domain: str = None, operation: str = None,
                   outcome: str = None, op_contains: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "oci_audit"}]
    if outcome:
        conds.append({"op": "equals", "field": "outcome", "value": outcome})
    if cadf_domain:
        conds.append({"op": "equals", "field": "service", "value": cadf_domain})
    if operation:
        conds.append({"op": "equals", "field": "operation", "value": operation})
    if op_contains and not operation:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def oci_vcn_cfg(dst_port=None, flow_action=None, dst_ports=None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "oci_vcn_flow"}]
    if flow_action:
        conds.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None:
        conds.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports:
        conds.append({"op": "in", "field": "network.dst_port",
                       "value": [str(p) for p in dst_ports]})
    return _cfg(conds)


def oci_cloudguard_cfg(severity: str = None, operation: str = None,
                        op_in: list = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "oci_cloudguard"}]
    if severity:
        conds.append({"op": "equals", "field": "severity", "value": severity})
    if operation:
        conds.append({"op": "equals", "field": "operation", "value": operation})
    if op_in:
        conds.append({"op": "in", "field": "operation", "value": op_in})
    return _cfg(conds)


def ibm_activity_cfg(service: str = None, op_contains: str = None,
                      outcome: str = None, operation: str = None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "ibm_activity"}]
    if outcome:
        conds.append({"op": "equals", "field": "outcome", "value": outcome})
    if service:
        conds.append({"op": "equals", "field": "service", "value": service})
    if operation:
        conds.append({"op": "contains", "field": "operation", "value": operation})
    if op_contains and not operation:
        conds.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(conds)


def ibm_vpc_cfg(dst_port=None, flow_action=None, dst_ports=None) -> str:
    conds = [{"op": "equals", "field": "source_type", "value": "ibm_vpc_flow"}]
    if flow_action:
        conds.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None:
        conds.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports:
        conds.append({"op": "in", "field": "network.dst_port",
                       "value": [str(p) for p in dst_ports]})
    return _cfg(conds)


# ---------------------------------------------------------------------------
# MITRE + severity lookup
# ---------------------------------------------------------------------------

MITRE_MAP = {
    'privilege_escalation': ('["privilege-escalation"]',            '["T1078","T1484","T1098"]'),
    'reconnaissance':       ('["reconnaissance","discovery"]',      '["T1595","T1526","T1087"]'),
    'authentication':       ('["initial-access","credential-access"]', '["T1078","T1110"]'),
    'authorization':        ('["defense-evasion","privilege-escalation"]', '["T1098","T1134"]'),
    'execute':              ('["execution"]',                        '["T1059","T1610"]'),
    'network':              ('["command-and-control","lateral-movement"]', '["T1046","T1071","T1133"]'),
    'threat':               ('["initial-access","execution","persistence"]', '["T1195","T1059"]'),
    'exfiltration':         ('["exfiltration"]',                    '["T1048","T1537"]'),
    'brute_force':          ('["credential-access"]',               '["T1110"]'),
    'c2':                   ('["command-and-control"]',             '["T1071","T1568"]'),
    'malware':              ('["execution","impact"]',              '["T1204","T1485"]'),
    'cryptomining':         ('["impact"]',                          '["T1496"]'),
}

SEV_MAP = {
    'privilege_escalation': ('critical', 90),
    'reconnaissance':       ('medium',   45),
    'authentication':       ('high',     70),
    'authorization':        ('high',     75),
    'execute':              ('high',     80),
    'network':              ('medium',   50),
    'threat':               ('high',     80),
    'exfiltration':         ('critical', 90),
    'brute_force':          ('critical', 85),
    'c2':                   ('critical', 95),
    'malware':              ('critical', 95),
    'cryptomining':         ('high',     75),
}


def emit(f, rule_id: str, service: str, provider: str, title: str, desc: str,
         cat: str, log_src: str, cfg: str):
    tactics, techniques = MITRE_MAP.get(cat, ('["persistence"]', '["T1098"]'))
    sev, risk = SEV_MAP.get(cat, ('medium', 55))

    f.write(
        f"INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)\n"
        f"VALUES ({sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},'log',true,{cfg})\n"
        f"ON CONFLICT DO NOTHING;\n\n"
    )
    f.write(
        f"INSERT INTO rule_metadata (\n"
        f"  rule_id,service,provider,severity,title,description,\n"
        f"  domain,subcategory,log_source_type,audit_log_event,action_category,\n"
        f"  rule_source,engines,primary_engine,\n"
        f"  mitre_tactics,mitre_techniques,risk_score,quality,csp\n"
        f") VALUES (\n"
        f"  {sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},\n"
        f"  {sql_str(sev)},{sql_str(title)},{sql_str(desc)},\n"
        f"  'threat_detection',{sql_str(cat)},{sql_str(log_src)},\n"
        f"  {sql_str(log_src + '_' + cat)},{sql_str(cat)},\n"
        f"  'log','{{\"ciem_engine\"}}','ciem_engine',\n"
        f"  '{tactics}','{techniques}',{risk},'auto',{sql_str(provider)}\n"
        f") ON CONFLICT DO NOTHING;\n\n"
    )


# ===========================================================================
# AZURE THREAT DETECTION RULES
# ===========================================================================

def generate_azure(out_dir: str):
    path = os.path.join(out_dir, "ciem_azure_threat_rules.sql")
    count = 0
    with open(path, "w") as f:
        f.write("-- CIEM Azure Threat Detection Rules\nBEGIN;\n\n")

        # ── Network: NSG Flow ──────────────────────────────────────────────
        net = [
            ("threat.azure.network.nsg_ssh_allow",  "nsg_flow", "azure",
             "Azure NSG: SSH Inbound Allowed",
             "SSH traffic (port 22) was allowed through an Azure Network Security Group. Review for unauthorized remote access.",
             "network", "azure_nsg_flow", azure_nsg_cfg(dst_port=22, flow_action="A")),
            ("threat.azure.network.nsg_rdp_allow",  "nsg_flow", "azure",
             "Azure NSG: RDP Inbound Allowed",
             "RDP traffic (port 3389) was allowed through an Azure NSG. Remote Desktop may expose systems to unauthorized access.",
             "network", "azure_nsg_flow", azure_nsg_cfg(dst_port=3389, flow_action="A")),
            ("threat.azure.network.nsg_smb_allow",  "nsg_flow", "azure",
             "Azure NSG: SMB Traffic Allowed",
             "SMB traffic (port 445) was allowed. Lateral movement via SMB is a common ransomware vector.",
             "network", "azure_nsg_flow", azure_nsg_cfg(dst_port=445, flow_action="A")),
            ("threat.azure.network.nsg_db_allow",   "nsg_flow", "azure",
             "Azure NSG: Database Port Exposed",
             "Database ports (1433/3306/5432/1521/27017) were allowed through an Azure NSG from outside.",
             "network", "azure_nsg_flow",
             azure_nsg_cfg(dst_ports=[1433, 3306, 5432, 1521, 27017], flow_action="A")),
            ("threat.azure.network.nsg_ssh_deny",   "nsg_flow", "azure",
             "Azure NSG: SSH Traffic Blocked — Possible Brute Force",
             "SSH traffic (port 22) was denied by an Azure NSG, indicating potential brute-force or scanning activity.",
             "brute_force", "azure_nsg_flow", azure_nsg_cfg(dst_port=22, flow_action="D")),
            ("threat.azure.network.nsg_rdp_deny",   "nsg_flow", "azure",
             "Azure NSG: RDP Traffic Blocked — Possible Brute Force",
             "RDP traffic (port 3389) was denied by an Azure NSG, indicating potential brute-force or scanning activity.",
             "brute_force", "azure_nsg_flow", azure_nsg_cfg(dst_port=3389, flow_action="D")),
            ("threat.azure.network.nsg_smb_deny",   "nsg_flow", "azure",
             "Azure NSG: SMB Traffic Blocked",
             "SMB traffic (port 445) was denied, possibly blocking lateral movement or ransomware propagation.",
             "network", "azure_nsg_flow", azure_nsg_cfg(dst_port=445, flow_action="D")),
            ("threat.azure.network.nsg_rejected",   "nsg_flow", "azure",
             "Azure NSG: Traffic Denied",
             "Network traffic was denied by an Azure NSG rule. Unexpected deny patterns may indicate scanning or attack.",
             "network", "azure_nsg_flow", azure_nsg_cfg(flow_action="D")),
            ("threat.azure.network.nsg_dns_allow",  "nsg_flow", "azure",
             "Azure NSG: DNS Traffic Allowed",
             "DNS traffic (port 53) allowed through NSG. Large volumes or external DNS may indicate C2 tunneling.",
             "network", "azure_nsg_flow", azure_nsg_cfg(dst_port=53, flow_action="A")),
        ]
        for args in net:
            emit(f, *args)
            count += 1

        # ── Threat: Azure Defender ────────────────────────────────────────
        defender = [
            ("threat.azure.threat.defender_critical",       "defender", "azure",
             "Azure Defender: Critical Security Alert",
             "Microsoft Defender for Cloud raised a Critical severity security alert. Immediate investigation required.",
             "threat", "azure_defender", azure_defender_cfg(severity="Critical")),
            ("threat.azure.threat.defender_high",           "defender", "azure",
             "Azure Defender: High Severity Security Alert",
             "Microsoft Defender for Cloud raised a High severity security alert.",
             "threat", "azure_defender", azure_defender_cfg(severity="High")),
            ("threat.azure.threat.defender_malware",        "defender", "azure",
             "Azure Defender: Malware Detected",
             "Microsoft Defender for Cloud detected malware activity on an Azure resource.",
             "malware", "azure_defender", azure_defender_cfg(op_contains="Malware")),
            ("threat.azure.threat.defender_brute_force",    "defender", "azure",
             "Azure Defender: Brute Force Attack Detected",
             "Microsoft Defender for Cloud detected a brute force attack against an Azure resource.",
             "brute_force", "azure_defender", azure_defender_cfg(op_contains="Brute")),
            ("threat.azure.threat.defender_credential_access", "defender", "azure",
             "Azure Defender: Credential Access Attempt",
             "Microsoft Defender for Cloud detected a credential access attempt, possible credential theft.",
             "authentication", "azure_defender", azure_defender_cfg(op_contains="CredentialAccess")),
            ("threat.azure.threat.defender_privilege_esc",  "defender", "azure",
             "Azure Defender: Privilege Escalation Detected",
             "Microsoft Defender for Cloud detected a privilege escalation attempt.",
             "privilege_escalation", "azure_defender", azure_defender_cfg(op_contains="PrivilegeEscalation")),
            ("threat.azure.threat.defender_data_exfil",     "defender", "azure",
             "Azure Defender: Data Exfiltration Detected",
             "Microsoft Defender for Cloud detected a data exfiltration attempt from an Azure resource.",
             "exfiltration", "azure_defender", azure_defender_cfg(op_contains="DataExfiltration")),
            ("threat.azure.threat.defender_anomalous_access", "defender", "azure",
             "Azure Defender: Anomalous Resource Access",
             "Microsoft Defender for Cloud detected anomalous access patterns to Azure resources.",
             "reconnaissance", "azure_defender", azure_defender_cfg(op_contains="AnomalousAccess")),
            ("threat.azure.threat.defender_suspicious_login", "defender", "azure",
             "Azure Defender: Suspicious Login Activity",
             "Microsoft Defender for Cloud detected suspicious login activity, possible account compromise.",
             "authentication", "azure_defender", azure_defender_cfg(op_contains="SuspiciousLogin")),
        ]
        for args in defender:
            emit(f, *args)
            count += 1

        # ── Execute: AKS Audit ────────────────────────────────────────────
        aks = [
            ("threat.azure.execute.aks_pod_exec",       "aks", "azure",
             "Azure AKS: Pod Exec Command Executed",
             "An exec command was run inside an AKS pod. This may indicate container breakout or lateral movement.",
             "execute", "azure_aks_audit", azure_aks_cfg("pods/exec")),
            ("threat.azure.execute.aks_pod_attach",     "aks", "azure",
             "Azure AKS: Pod Attach Session",
             "A process attached to a running AKS pod. Review for unauthorized container access.",
             "execute", "azure_aks_audit", azure_aks_cfg("pods/attach")),
            ("threat.azure.execute.aks_portforward",    "aks", "azure",
             "Azure AKS: Port Forwarding Established",
             "Port forwarding was set up to an AKS pod, potentially exposing internal services.",
             "execute", "azure_aks_audit", azure_aks_cfg("pods/portforward")),
            ("threat.azure.execute.aks_privileged_pod", "aks", "azure",
             "Azure AKS: Privileged Pod Created",
             "A privileged pod was created in AKS. Privileged containers can escape to the host node.",
             "execute", "azure_aks_audit", azure_aks_cfg("privileged")),
        ]
        for args in aks:
            emit(f, *args)
            count += 1

        # ── Privilege Escalation: Azure Activity ──────────────────────────
        privesc = [
            ("threat.azure.privilege_escalation.elevate_access",   "authorization", "azure",
             "Azure: Global Admin Elevation of Access",
             "User activated Global Administrator access via elevateAccess. This grants full Azure AD and subscription access.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(op_contains="elevateAccess")),
            ("threat.azure.privilege_escalation.role_assignment",   "authorization", "azure",
             "Azure: Role Assignment Created",
             "A new Azure RBAC role assignment was created. Unauthorized role assignments grant persistent access.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(arm_op="Microsoft.Authorization/roleAssignments/write")),
            ("threat.azure.privilege_escalation.custom_role",       "authorization", "azure",
             "Azure: Custom Role Definition Created or Modified",
             "An Azure custom RBAC role was created or updated. Malicious custom roles can grant excessive permissions.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(op_contains="roleDefinitions/write")),
            ("threat.azure.privilege_escalation.policy_assignment", "authorization", "azure",
             "Azure: Policy Assignment Created",
             "An Azure Policy was assigned at subscription or resource group scope. Policies can enforce or allow dangerous configurations.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(arm_op="Microsoft.Authorization/policyAssignments/write")),
            ("threat.azure.privilege_escalation.classic_admin",     "authorization", "azure",
             "Azure: Classic Administrator Added",
             "A classic co-administrator was added to the Azure subscription, granting owner-level access.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(op_contains="classicAdministrators/write")),
            ("threat.azure.privilege_escalation.management_group",  "management", "azure",
             "Azure: Management Group Modification",
             "An Azure Management Group was modified. Changes at management group level affect all child subscriptions.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(op_contains="Microsoft.Management/managementGroups")),
            ("threat.azure.privilege_escalation.lock_delete",       "authorization", "azure",
             "Azure: Resource Lock Deleted",
             "An Azure resource lock was deleted, removing protection from accidental or unauthorized resource deletion.",
             "privilege_escalation", "azure_activity",
             azure_activity_cfg(op_contains="locks/delete")),
        ]
        for args in privesc:
            emit(f, *args)
            count += 1

        # ── Reconnaissance: Azure Activity (outcome=failure) ─────────────
        recon = [
            ("threat.azure.reconnaissance.keyvault_secret_failed",  "keyvault", "azure",
             "Azure Key Vault: Failed Secret Access",
             "Unauthorized attempt to read a Key Vault secret was denied. May indicate credential harvesting.",
             "reconnaissance", "azure_activity",
             azure_activity_cfg(op_contains="vaults/secrets", outcome="failure")),
            ("threat.azure.reconnaissance.keyvault_key_failed",     "keyvault", "azure",
             "Azure Key Vault: Failed Key Access",
             "Unauthorized attempt to read a Key Vault cryptographic key was denied.",
             "reconnaissance", "azure_activity",
             azure_activity_cfg(op_contains="vaults/keys", outcome="failure")),
            ("threat.azure.reconnaissance.keyvault_cert_failed",    "keyvault", "azure",
             "Azure Key Vault: Failed Certificate Access",
             "Unauthorized attempt to read a Key Vault certificate was denied.",
             "reconnaissance", "azure_activity",
             azure_activity_cfg(op_contains="vaults/certificates", outcome="failure")),
            ("threat.azure.reconnaissance.storage_list_keys",       "storage", "azure",
             "Azure Storage: Account Keys Listed",
             "Storage account keys were listed. This operation retrieves secrets that grant full storage access.",
             "reconnaissance", "azure_activity",
             azure_activity_cfg(op_contains="listKeys/action")),
            ("threat.azure.reconnaissance.authorization_failed",    "authorization", "azure",
             "Azure Authorization: Access Check Failed",
             "Multiple authorization check failures detected, indicating potential access probing.",
             "reconnaissance", "azure_activity",
             azure_activity_cfg(service="authorization", outcome="failure")),
        ]
        for args in recon:
            emit(f, *args)
            count += 1

        # ── Authentication Failures: Azure Activity ───────────────────────
        auth = [
            ("threat.azure.authentication.compute_failed",    "compute", "azure",
             "Azure Compute: Authentication Failure",
             "An Azure Compute operation failed due to authentication/authorization error.",
             "authentication", "azure_activity",
             azure_activity_cfg(service="compute", outcome="failure")),
            ("threat.azure.authentication.keyvault_failed",   "keyvault", "azure",
             "Azure Key Vault: Access Policy Authentication Failure",
             "Key Vault access policy operation failed, possible unauthorized access attempt.",
             "authentication", "azure_activity",
             azure_activity_cfg(op_contains="accessPolicies", outcome="failure")),
            ("threat.azure.authentication.network_failed",    "network", "azure",
             "Azure Network: Authentication Failure",
             "An Azure Network operation failed due to authentication/authorization error.",
             "authentication", "azure_activity",
             azure_activity_cfg(service="network", outcome="failure")),
        ]
        for args in auth:
            emit(f, *args)
            count += 1

        # ── Exfiltration: Azure Activity ──────────────────────────────────
        exfil = [
            ("threat.azure.exfiltration.storage_sas_list",  "storage", "azure",
             "Azure Storage: SAS Token Generated",
             "A Storage Account SAS token was listed/created. SAS tokens can be used for unauthorized data exfiltration.",
             "exfiltration", "azure_activity",
             azure_activity_cfg(op_contains="listServiceSas/action")),
            ("threat.azure.exfiltration.disk_export_access", "compute", "azure",
             "Azure Compute: Disk Export Access Granted",
             "A managed disk export access was granted, enabling data extraction from a VM disk.",
             "exfiltration", "azure_activity",
             azure_activity_cfg(op_contains="exportDiskAccess/action")),
            ("threat.azure.exfiltration.cert_backup",        "keyvault", "azure",
             "Azure Key Vault: Certificate Backup Created",
             "A Key Vault certificate backup was created. Backups contain exportable private key material.",
             "exfiltration", "azure_activity",
             azure_activity_cfg(op_contains="certificates/backup/action")),
            ("threat.azure.exfiltration.db_export",          "sql", "azure",
             "Azure SQL: Database Export Initiated",
             "An Azure SQL database export operation was initiated. Large-scale data export may indicate exfiltration.",
             "exfiltration", "azure_activity",
             azure_activity_cfg(op_contains="exportRequest/action")),
        ]
        for args in exfil:
            emit(f, *args)
            count += 1

        f.write("COMMIT;\n")
    print(f"Azure threat rules: {count} → {path}")
    return count


# ===========================================================================
# GCP THREAT DETECTION RULES
# ===========================================================================

def generate_gcp(out_dir: str):
    path = os.path.join(out_dir, "ciem_gcp_threat_rules.sql")
    count = 0
    with open(path, "w") as f:
        f.write("-- CIEM GCP Threat Detection Rules\nBEGIN;\n\n")

        # ── Network: GCP VPC Flow ─────────────────────────────────────────
        net = [
            ("threat.gcp.network.vpc_ssh_allow",  "vpc_flow", "gcp",
             "GCP VPC: SSH Traffic Allowed",
             "SSH traffic (port 22) was allowed through GCP VPC firewall. Review for unauthorized remote access.",
             "network", "gcp_vpc_flow", gcp_flow_cfg(dst_port=22, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_rdp_allow",  "vpc_flow", "gcp",
             "GCP VPC: RDP Traffic Allowed",
             "RDP traffic (port 3389) was allowed through GCP VPC firewall. Remote Desktop may expose systems.",
             "network", "gcp_vpc_flow", gcp_flow_cfg(dst_port=3389, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_db_allow",   "vpc_flow", "gcp",
             "GCP VPC: Database Port Exposed",
             "Database ports (3306/5432/1433/27017/6379) were allowed through GCP VPC firewall.",
             "network", "gcp_vpc_flow",
             gcp_flow_cfg(dst_ports=[3306, 5432, 1433, 27017, 6379], flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_dns",        "vpc_flow", "gcp",
             "GCP VPC: DNS Traffic Detected",
             "DNS traffic (port 53) detected. Unusual DNS traffic volumes may indicate C2 tunneling.",
             "network", "gcp_vpc_flow", gcp_flow_cfg(dst_port=53)),
            ("threat.gcp.network.vpc_ssh_denied", "vpc_flow", "gcp",
             "GCP VPC: SSH Traffic Blocked — Possible Brute Force",
             "SSH traffic (port 22) was denied by GCP VPC firewall, indicating brute-force or scanning activity.",
             "brute_force", "gcp_vpc_flow", gcp_flow_cfg(dst_port=22, flow_action="DENIED")),
            ("threat.gcp.network.vpc_rdp_denied", "vpc_flow", "gcp",
             "GCP VPC: RDP Traffic Blocked — Possible Brute Force",
             "RDP traffic (port 3389) was denied by GCP VPC firewall, indicating brute-force or scanning.",
             "brute_force", "gcp_vpc_flow", gcp_flow_cfg(dst_port=3389, flow_action="DENIED")),
            ("threat.gcp.network.vpc_rejected",   "vpc_flow", "gcp",
             "GCP VPC: Traffic Denied by Firewall",
             "Network traffic was denied by a GCP VPC firewall rule. Repeated denies may indicate port scanning.",
             "network", "gcp_vpc_flow", gcp_flow_cfg(flow_action="DENIED")),
        ]
        for args in net:
            emit(f, *args)
            count += 1

        # ── Threat: GCP Security Command Center ───────────────────────────
        scc = [
            ("threat.gcp.threat.scc_critical",         "scc", "gcp",
             "GCP SCC: Critical Security Finding",
             "Google Cloud Security Command Center raised a Critical severity finding. Immediate investigation required.",
             "threat", "gcp_scc", gcp_scc_cfg(severity="CRITICAL")),
            ("threat.gcp.threat.scc_high",             "scc", "gcp",
             "GCP SCC: High Severity Security Finding",
             "Google Cloud Security Command Center raised a High severity security finding.",
             "threat", "gcp_scc", gcp_scc_cfg(severity="HIGH")),
            ("threat.gcp.threat.scc_anomalous_access", "scc", "gcp",
             "GCP SCC: Anomalous Access Detected",
             "GCP Security Command Center detected anomalous access patterns to Google Cloud resources.",
             "reconnaissance", "gcp_scc", gcp_scc_cfg(op_contains="ANOMALOUS_ACCESS")),
            ("threat.gcp.threat.scc_brute_force",      "scc", "gcp",
             "GCP SCC: Brute Force Attack Detected",
             "GCP Security Command Center detected a brute force attack against GCP resources.",
             "brute_force", "gcp_scc", gcp_scc_cfg(op_contains="BRUTE_FORCE")),
            ("threat.gcp.threat.scc_cryptomining",     "scc", "gcp",
             "GCP SCC: Cryptomining Activity Detected",
             "GCP Security Command Center detected cryptomining activity on a GCP resource.",
             "cryptomining", "gcp_scc", gcp_scc_cfg(op_contains="CRYPTO_MINING")),
            ("threat.gcp.threat.scc_data_exfil",       "scc", "gcp",
             "GCP SCC: Data Exfiltration Detected",
             "GCP Security Command Center detected a data exfiltration event from GCP resources.",
             "exfiltration", "gcp_scc", gcp_scc_cfg(op_contains="DATA_EXFILTRATION")),
            ("threat.gcp.threat.scc_malware",          "scc", "gcp",
             "GCP SCC: Malware Detected",
             "GCP Security Command Center detected malware activity on a GCP resource.",
             "malware", "gcp_scc", gcp_scc_cfg(op_contains="MALWARE")),
            ("threat.gcp.threat.scc_misconfiguration", "scc", "gcp",
             "GCP SCC: Security Misconfiguration",
             "GCP Security Command Center identified a security misconfiguration in GCP resources.",
             "threat", "gcp_scc", gcp_scc_cfg(op_contains="MISCONFIGURATION")),
            ("threat.gcp.threat.scc_policy_violation", "scc", "gcp",
             "GCP SCC: Policy Violation Detected",
             "GCP Security Command Center detected a policy violation in GCP resource configuration.",
             "threat", "gcp_scc", gcp_scc_cfg(op_contains="POLICY_VIOLATION")),
        ]
        for args in scc:
            emit(f, *args)
            count += 1

        # ── Execute: GKE Audit ────────────────────────────────────────────
        gke = [
            ("threat.gcp.execute.gke_pod_exec",     "gke", "gcp",
             "GCP GKE: Pod Exec Command Executed",
             "An exec command was run inside a GKE pod. Review for container breakout or lateral movement.",
             "execute", "gcp_gke_audit", gcp_gke_cfg("pods/exec")),
            ("threat.gcp.execute.gke_pod_attach",   "gke", "gcp",
             "GCP GKE: Pod Attach Session",
             "A process attached to a running GKE pod. May indicate unauthorized container access.",
             "execute", "gcp_gke_audit", gcp_gke_cfg("pods/attach")),
            ("threat.gcp.execute.gke_portforward",  "gke", "gcp",
             "GCP GKE: Port Forwarding Established",
             "Port forwarding was established to a GKE pod, potentially exposing internal GCP services.",
             "execute", "gcp_gke_audit", gcp_gke_cfg("pods/portforward")),
        ]
        for args in gke:
            emit(f, *args)
            count += 1

        # ── Privilege Escalation: GCP Audit ───────────────────────────────
        privesc = [
            ("threat.gcp.privilege_escalation.set_iam_policy",     "iam", "gcp",
             "GCP IAM: Policy Binding Modified (setIamPolicy)",
             "An IAM policy was modified via setIamPolicy. Unauthorized bindings grant persistent privileged access.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(operation="setIamPolicy")),
            ("threat.gcp.privilege_escalation.sa_key_create",      "iam", "gcp",
             "GCP IAM: Service Account Key Created",
             "A service account key was created. Keys provide long-lived credentials outside the GCP console.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(service_uri="iam.googleapis.com", operation="CreateServiceAccountKey")),
            ("threat.gcp.privilege_escalation.sa_token_generate",  "iam", "gcp",
             "GCP IAM: Service Account Access Token Generated",
             "An access token was generated for a service account, potentially for privilege escalation.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(service_uri="iamcredentials.googleapis.com", operation="GenerateAccessToken")),
            ("threat.gcp.privilege_escalation.create_role",        "iam", "gcp",
             "GCP IAM: Custom Role Created",
             "A custom IAM role was created. Malicious custom roles can grant excessive permissions.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(service_uri="iam.googleapis.com", operation="CreateRole")),
            ("threat.gcp.privilege_escalation.workload_identity",  "iam", "gcp",
             "GCP IAM: Workload Identity Pool Modified",
             "A Workload Identity Pool was created or modified, potentially allowing external identities to assume GCP roles.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(service_uri="iam.googleapis.com", operation="workloadIdentityPools")),
            ("threat.gcp.privilege_escalation.org_policy_set",     "cloudresourcemanager", "gcp",
             "GCP: Organization Policy Set",
             "An organization-level policy was set. Changes to org policies can affect all projects under the org.",
             "privilege_escalation", "gcp_audit",
             gcp_audit_cfg(service_uri="cloudresourcemanager.googleapis.com", operation="SetOrgPolicy")),
        ]
        for args in privesc:
            emit(f, *args)
            count += 1

        # ── Reconnaissance: GCP Audit (outcome=failure) ───────────────────
        recon = [
            ("threat.gcp.reconnaissance.secret_access_failed", "secretmanager", "gcp",
             "GCP Secret Manager: Unauthorized Secret Access",
             "Unauthorized attempt to access a GCP Secret Manager secret was denied.",
             "reconnaissance", "gcp_audit",
             gcp_audit_cfg(service_uri="secretmanager.googleapis.com", outcome="failure")),
            ("threat.gcp.reconnaissance.storage_failed",       "storage", "gcp",
             "GCP Storage: Unauthorized Bucket Operation",
             "Unauthorized attempt to access a GCP Cloud Storage bucket was denied.",
             "reconnaissance", "gcp_audit",
             gcp_audit_cfg(service_uri="storage.googleapis.com", outcome="failure")),
            ("threat.gcp.reconnaissance.iam_failed",           "iam", "gcp",
             "GCP IAM: Unauthorized Operation",
             "Unauthorized IAM operation was denied, possibly indicating privilege enumeration.",
             "reconnaissance", "gcp_audit",
             gcp_audit_cfg(service_uri="iam.googleapis.com", outcome="failure")),
            ("threat.gcp.reconnaissance.kms_failed",           "cloudkms", "gcp",
             "GCP KMS: Unauthorized Key Operation",
             "Unauthorized attempt to access a GCP KMS key was denied. May indicate key extraction attempt.",
             "reconnaissance", "gcp_audit",
             gcp_audit_cfg(service_uri="cloudkms.googleapis.com", outcome="failure")),
        ]
        for args in recon:
            emit(f, *args)
            count += 1

        # ── Authentication: GCP Audit ─────────────────────────────────────
        auth = [
            ("threat.gcp.authentication.compute_auth_failed",  "compute", "gcp",
             "GCP Compute: Authentication Failure",
             "A GCP Compute Engine operation failed due to authentication error.",
             "authentication", "gcp_audit",
             gcp_audit_cfg(service_uri="compute.googleapis.com", outcome="failure")),
            ("threat.gcp.authentication.container_auth_failed", "container", "gcp",
             "GCP Container: Authentication Failure",
             "A GCP Container/GKE operation failed due to authentication error.",
             "authentication", "gcp_audit",
             gcp_audit_cfg(service_uri="container.googleapis.com", outcome="failure")),
        ]
        for args in auth:
            emit(f, *args)
            count += 1

        # ── Exfiltration: GCP Audit ───────────────────────────────────────
        exfil = [
            ("threat.gcp.exfiltration.storage_hmac_create",  "storage", "gcp",
             "GCP Storage: HMAC Key Created",
             "A Cloud Storage HMAC key was created. HMAC keys provide programmatic access for data exfiltration.",
             "exfiltration", "gcp_audit",
             gcp_audit_cfg(service_uri="storage.googleapis.com", operation="CreateHmacKey")),
            ("threat.gcp.exfiltration.bigquery_export",      "bigquery", "gcp",
             "GCP BigQuery: Data Extract/Export",
             "A BigQuery data extraction or export job was created, potentially indicating data exfiltration.",
             "exfiltration", "gcp_audit",
             gcp_audit_cfg(service_uri="bigquery.googleapis.com", operation="Extract")),
            ("threat.gcp.exfiltration.secret_access",        "secretmanager", "gcp",
             "GCP Secret Manager: Secret Accessed",
             "A secret was accessed from GCP Secret Manager. Review for unauthorized credential access.",
             "exfiltration", "gcp_audit",
             gcp_audit_cfg(service_uri="secretmanager.googleapis.com", operation="AccessSecretVersion")),
        ]
        for args in exfil:
            emit(f, *args)
            count += 1

        f.write("COMMIT;\n")
    print(f"GCP threat rules: {count} → {path}")
    return count


# ===========================================================================
# OCI THREAT DETECTION RULES
# ===========================================================================

OCI_IDENTITY = "com.oraclecloud.identitycontrolplane"
OCI_COMPUTE  = "com.oraclecloud.computeapi"
OCI_VAULT    = "com.oraclecloud.vaultmng"
OCI_NETWORK  = "com.oraclecloud.virtualnetwork"
OCI_BASTION  = "com.oraclecloud.bastion"
OCI_OKE      = "com.oraclecloud.containerengine"
OCI_OBJECT   = "com.oraclecloud.objectstorage"
OCI_FUNCS    = "com.oraclecloud.functions"


def generate_oci(out_dir: str):
    path = os.path.join(out_dir, "ciem_oci_threat_rules.sql")
    count = 0
    with open(path, "w") as f:
        f.write("-- CIEM OCI Threat Detection Rules\nBEGIN;\n\n")

        # ── Network: OCI VCN Flow ─────────────────────────────────────────
        net = [
            ("threat.oci.network.vcn_ssh_accept",  "vcn_flow", "oci",
             "OCI VCN: SSH Traffic Allowed",
             "SSH traffic (port 22) was allowed through an OCI VCN Security List or NSG.",
             "network", "oci_vcn_flow", oci_vcn_cfg(dst_port=22, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_rdp_accept",  "vcn_flow", "oci",
             "OCI VCN: RDP Traffic Allowed",
             "RDP traffic (port 3389) was allowed through an OCI VCN Security List or NSG.",
             "network", "oci_vcn_flow", oci_vcn_cfg(dst_port=3389, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_db_accept",   "vcn_flow", "oci",
             "OCI VCN: Database Port Exposed",
             "Database ports (3306/5432/1521/27017/6379) were allowed through OCI VCN.",
             "network", "oci_vcn_flow",
             oci_vcn_cfg(dst_ports=[3306, 5432, 1521, 27017, 6379], flow_action="ACCEPT")),
            ("threat.oci.network.vcn_dns",         "vcn_flow", "oci",
             "OCI VCN: DNS Traffic Detected",
             "DNS traffic (port 53) detected through OCI VCN. May indicate C2 tunneling if volumes are high.",
             "network", "oci_vcn_flow", oci_vcn_cfg(dst_port=53)),
            ("threat.oci.network.vcn_ssh_reject",  "vcn_flow", "oci",
             "OCI VCN: SSH Traffic Blocked — Possible Brute Force",
             "SSH traffic (port 22) was rejected by OCI VCN, indicating brute-force or scanning activity.",
             "brute_force", "oci_vcn_flow", oci_vcn_cfg(dst_port=22, flow_action="REJECT")),
            ("threat.oci.network.vcn_rdp_reject",  "vcn_flow", "oci",
             "OCI VCN: RDP Traffic Blocked — Possible Brute Force",
             "RDP traffic (port 3389) was rejected by OCI VCN, indicating brute-force or scanning activity.",
             "brute_force", "oci_vcn_flow", oci_vcn_cfg(dst_port=3389, flow_action="REJECT")),
            ("threat.oci.network.vcn_rejected",    "vcn_flow", "oci",
             "OCI VCN: Traffic Rejected",
             "Network traffic was rejected by OCI VCN rules. Unusual reject patterns may indicate port scanning.",
             "network", "oci_vcn_flow", oci_vcn_cfg(flow_action="REJECT")),
        ]
        for args in net:
            emit(f, *args)
            count += 1

        # ── Threat: OCI Cloud Guard ───────────────────────────────────────
        cg = [
            ("threat.oci.threat.cloudguard_critical",        "cloudguard", "oci",
             "OCI Cloud Guard: Critical Problem Detected",
             "Oracle Cloud Guard detected a Critical severity security problem. Immediate action required.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(severity="CRITICAL", operation="ProblemDetected")),
            ("threat.oci.threat.cloudguard_high",            "cloudguard", "oci",
             "OCI Cloud Guard: High Severity Problem Detected",
             "Oracle Cloud Guard detected a High severity security problem in OCI resources.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(severity="HIGH", operation="ProblemDetected")),
            ("threat.oci.threat.cloudguard_threat",          "cloudguard", "oci",
             "OCI Cloud Guard: Threat Detected",
             "Oracle Cloud Guard raised a threat detection event for an OCI resource.",
             "threat", "oci_cloudguard", oci_cloudguard_cfg(operation="ThreatDetected")),
            ("threat.oci.threat.cloudguard_security_zone",   "cloudguard", "oci",
             "OCI Cloud Guard: Security Zone Violation",
             "An OCI Security Zone policy violation was detected. Resources must conform to security zone requirements.",
             "threat", "oci_cloudguard", oci_cloudguard_cfg(operation="SecurityZoneViolation")),
            ("threat.oci.threat.cloudguard_responder",       "cloudguard", "oci",
             "OCI Cloud Guard: Responder Executed",
             "A Cloud Guard Responder was triggered in response to a security problem.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(op_in=["ResponderExecuted", "TriggerResponder"])),
            ("threat.oci.threat.cloudguard_detector_change", "cloudguard", "oci",
             "OCI Cloud Guard: Detector Recipe Modified",
             "A Cloud Guard Detector Recipe was created, updated, or deleted, potentially disabling threat detection.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(op_in=["UpdateDetectorRecipe", "DeleteDetectorRecipe", "CreateDetectorRecipe"])),
            ("threat.oci.threat.cloudguard_target_change",   "cloudguard", "oci",
             "OCI Cloud Guard: Target Configuration Modified",
             "A Cloud Guard monitoring target was modified. Changes may reduce security monitoring coverage.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(op_in=["UpdateTarget", "DeleteTarget", "CreateTarget"])),
            ("threat.oci.threat.cloudguard_managed_list",    "cloudguard", "oci",
             "OCI Cloud Guard: Managed List Modified",
             "A Cloud Guard Managed List (trusted IPs, approved resources) was modified.",
             "threat", "oci_cloudguard",
             oci_cloudguard_cfg(op_in=["UpdateManagedList", "DeleteManagedList", "CreateManagedList"])),
        ]
        for args in cg:
            emit(f, *args)
            count += 1

        # ── Privilege Escalation: OCI Audit ───────────────────────────────
        privesc = [
            ("threat.oci.privilege_escalation.policy_create",    "identity", "oci",
             "OCI IAM: Policy Created",
             "A new OCI IAM policy was created. Policies control access to all OCI resources.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="CreatePolicy")),
            ("threat.oci.privilege_escalation.policy_update",    "identity", "oci",
             "OCI IAM: Policy Updated",
             "An OCI IAM policy was updated, potentially granting additional permissions.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="UpdatePolicy")),
            ("threat.oci.privilege_escalation.group_member_add", "identity", "oci",
             "OCI IAM: User Added to Group",
             "A user was added to an OCI IAM group, inheriting all group permissions.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="AddUserToGroup")),
            ("threat.oci.privilege_escalation.api_key_create",   "identity", "oci",
             "OCI IAM: API Key Created",
             "A new API signing key was added to an OCI user. API keys provide persistent programmatic access.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="UploadApiKey")),
            ("threat.oci.privilege_escalation.auth_token_create","identity", "oci",
             "OCI IAM: Auth Token Created",
             "A new auth token was created for an OCI user. Auth tokens are used for Swift API access.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="CreateAuthToken")),
            ("threat.oci.privilege_escalation.user_created",     "identity", "oci",
             "OCI IAM: New User Created",
             "A new OCI IAM user was created. Review for unauthorized account creation.",
             "privilege_escalation", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="CreateUser")),
        ]
        for args in privesc:
            emit(f, *args)
            count += 1

        # ── Authentication: OCI Audit (outcome=failure) ───────────────────
        auth = [
            ("threat.oci.authentication.identity_failed",  "identity", "oci",
             "OCI IAM: Authentication Failure",
             "An OCI IAM operation failed with an authentication error. Review for unauthorized access attempts.",
             "authentication", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, outcome="failure")),
            ("threat.oci.authentication.compute_failed",   "compute", "oci",
             "OCI Compute: Authentication Failure",
             "An OCI Compute operation failed with an authentication error.",
             "authentication", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_COMPUTE, outcome="failure")),
        ]
        for args in auth:
            emit(f, *args)
            count += 1

        # ── Execute: OCI Audit ────────────────────────────────────────────
        execute = [
            ("threat.oci.execute.bastion_session",      "bastion", "oci",
             "OCI Bastion: Session Created",
             "A Bastion Service session was created to access OCI resources. Review session targets and users.",
             "execute", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_BASTION, operation="CreateSession")),
            ("threat.oci.execute.instance_console",     "compute", "oci",
             "OCI Compute: Instance Console Connection Created",
             "A console connection to an OCI compute instance was established. May indicate unauthorized instance access.",
             "execute", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_COMPUTE, operation="CreateInstanceConsoleConnection")),
            ("threat.oci.execute.oke_node_pool_create", "containerengine", "oci",
             "OCI OKE: Node Pool Created",
             "A new OKE (Kubernetes) node pool was created. Review for unauthorized cluster expansion.",
             "execute", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_OKE, operation="CreateNodePool")),
        ]
        for args in execute:
            emit(f, *args)
            count += 1

        # ── Reconnaissance: OCI Audit ─────────────────────────────────────
        recon = [
            ("threat.oci.reconnaissance.vault_secret_list", "vault", "oci",
             "OCI Vault: Secrets Listed",
             "Secrets in OCI Vault were listed. Enumeration of secrets may precede credential theft.",
             "reconnaissance", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_VAULT, operation="ListSecrets")),
            ("threat.oci.reconnaissance.policy_list",       "identity", "oci",
             "OCI IAM: Policies Listed",
             "OCI IAM policies were listed. Policy enumeration is a common reconnaissance technique.",
             "reconnaissance", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="ListPolicies")),
            ("threat.oci.reconnaissance.user_list",         "identity", "oci",
             "OCI IAM: Users Listed",
             "OCI IAM users were listed. User enumeration may indicate reconnaissance of the identity plane.",
             "reconnaissance", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_IDENTITY, operation="ListUsers")),
        ]
        for args in recon:
            emit(f, *args)
            count += 1

        # ── Exfiltration: OCI Audit ───────────────────────────────────────
        exfil = [
            ("threat.oci.exfiltration.bucket_public_access", "objectstorage", "oci",
             "OCI Object Storage: Bucket Made Public",
             "An OCI Object Storage bucket was made publicly accessible, risking data exposure.",
             "exfiltration", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_OBJECT, operation="UpdateBucket")),
            ("threat.oci.exfiltration.pre_auth_request",     "objectstorage", "oci",
             "OCI Object Storage: Pre-Authenticated Request Created",
             "A pre-authenticated request was created for an OCI bucket, allowing external data access.",
             "exfiltration", "oci_audit",
             oci_audit_cfg(cadf_domain=OCI_OBJECT, operation="CreatePreauthenticatedRequest")),
        ]
        for args in exfil:
            emit(f, *args)
            count += 1

        f.write("COMMIT;\n")
    print(f"OCI threat rules: {count} → {path}")
    return count


# ===========================================================================
# IBM THREAT DETECTION RULES
# ===========================================================================

def generate_ibm(out_dir: str):
    path = os.path.join(out_dir, "ciem_ibm_threat_rules.sql")
    count = 0
    with open(path, "w") as f:
        f.write("-- CIEM IBM Threat Detection Rules\nBEGIN;\n\n")

        # ── Network: IBM VPC Flow ─────────────────────────────────────────
        net = [
            ("threat.ibm.network.vpc_ssh_accept",  "vpc_flow", "ibm",
             "IBM VPC: SSH Traffic Allowed",
             "SSH traffic (port 22) was allowed through IBM Cloud VPC network access controls.",
             "network", "ibm_vpc_flow", ibm_vpc_cfg(dst_port=22, flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_rdp_accept",  "vpc_flow", "ibm",
             "IBM VPC: RDP Traffic Allowed",
             "RDP traffic (port 3389) was allowed through IBM Cloud VPC network access controls.",
             "network", "ibm_vpc_flow", ibm_vpc_cfg(dst_port=3389, flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_db_accept",   "vpc_flow", "ibm",
             "IBM VPC: Database Port Exposed",
             "Database ports (3306/5432/1433/27017/6379) were allowed through IBM Cloud VPC.",
             "network", "ibm_vpc_flow",
             ibm_vpc_cfg(dst_ports=[3306, 5432, 1433, 27017, 6379], flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_dns",         "vpc_flow", "ibm",
             "IBM VPC: DNS Traffic Detected",
             "DNS traffic (port 53) detected through IBM VPC. High volumes may indicate C2 tunneling.",
             "network", "ibm_vpc_flow", ibm_vpc_cfg(dst_port=53)),
            ("threat.ibm.network.vpc_ssh_reject",  "vpc_flow", "ibm",
             "IBM VPC: SSH Traffic Blocked — Possible Brute Force",
             "SSH traffic (port 22) was rejected by IBM VPC, indicating brute-force or scanning activity.",
             "brute_force", "ibm_vpc_flow", ibm_vpc_cfg(dst_port=22, flow_action="REJECT")),
            ("threat.ibm.network.vpc_rejected",    "vpc_flow", "ibm",
             "IBM VPC: Traffic Rejected",
             "Network traffic was rejected by IBM VPC security rules. May indicate port scanning.",
             "network", "ibm_vpc_flow", ibm_vpc_cfg(flow_action="REJECT")),
        ]
        for args in net:
            emit(f, *args)
            count += 1

        # ── Privilege Escalation: IBM Activity ────────────────────────────
        privesc = [
            ("threat.ibm.privilege_escalation.iam_policy_create",     "iam_identity", "ibm",
             "IBM IAM: Policy Created",
             "A new IBM Cloud IAM access policy was created, granting permissions to identities.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam", operation="iam.policy.create")),
            ("threat.ibm.privilege_escalation.access_group_member",   "iam_identity", "ibm",
             "IBM IAM: User Added to Access Group",
             "A member was added to an IBM Cloud IAM Access Group, inheriting all group permissions.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam", operation="iam.access-group-member.create")),
            ("threat.ibm.privilege_escalation.service_api_key_create","iam_identity", "ibm",
             "IBM IAM: Service ID API Key Created",
             "An API key was created for an IBM Service ID. Service ID keys provide programmatic access.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", operation="iam-identity.serviceid-apikey.create")),
            ("threat.ibm.privilege_escalation.user_api_key_create",   "iam_identity", "ibm",
             "IBM IAM: User API Key Created",
             "An API key was created for an IBM Cloud user. API keys provide long-lived authentication credentials.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", operation="iam-identity.user-apikey.create")),
            ("threat.ibm.privilege_escalation.service_id_create",     "iam_identity", "ibm",
             "IBM IAM: Service ID Created",
             "A new IBM Cloud Service ID was created. Service IDs are used for programmatic API access.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", operation="iam-identity.serviceid.create")),
            ("threat.ibm.privilege_escalation.trusted_profile_create","iam_identity", "ibm",
             "IBM IAM: Trusted Profile Created",
             "A new IBM Cloud Trusted Profile was created, enabling federated access to IBM Cloud resources.",
             "privilege_escalation", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", operation="iam-identity.profile.create")),
        ]
        for args in privesc:
            emit(f, *args)
            count += 1

        # ── Authentication Failures: IBM Activity ─────────────────────────
        auth = [
            ("threat.ibm.authentication.login_failed",      "iam_identity", "ibm",
             "IBM IAM: User Login Failed",
             "An IBM Cloud user login failed. Repeated failures may indicate brute-force or account takeover.",
             "authentication", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", operation="iam-identity.user.login",
                               outcome="failure")),
            ("threat.ibm.authentication.api_key_failed",    "iam_identity", "ibm",
             "IBM IAM: API Key Authentication Failed",
             "Authentication using an IBM Cloud API key failed. May indicate key rotation needed or attack.",
             "authentication", "ibm_activity",
             ibm_activity_cfg(service="iam_identity", outcome="failure",
                               op_contains="iam-identity")),
            ("threat.ibm.authentication.iam_auth_failed",   "iam", "ibm",
             "IBM IAM: Authorization Failed",
             "An IBM Cloud IAM authorization check failed. May indicate privilege probing.",
             "authentication", "ibm_activity",
             ibm_activity_cfg(service="iam", outcome="failure")),
        ]
        for args in auth:
            emit(f, *args)
            count += 1

        # ── Reconnaissance: IBM Activity ──────────────────────────────────
        recon = [
            ("threat.ibm.reconnaissance.kms_key_list",    "kms", "ibm",
             "IBM KMS: Encryption Keys Listed",
             "IBM Key Protect encryption keys were listed. Key enumeration may precede key extraction attempts.",
             "reconnaissance", "ibm_activity",
             ibm_activity_cfg(service="kms", operation="kms.secrets.list")),
            ("threat.ibm.reconnaissance.secrets_list",    "secrets_manager", "ibm",
             "IBM Secrets Manager: Secrets Listed",
             "Secrets in IBM Secrets Manager were listed. Enumeration may precede unauthorized secret access.",
             "reconnaissance", "ibm_activity",
             ibm_activity_cfg(service="secrets_manager", operation="secrets-manager.secret.list")),
            ("threat.ibm.reconnaissance.iam_policy_list", "iam", "ibm",
             "IBM IAM: Policies Listed",
             "IBM Cloud IAM policies were listed. Policy enumeration is a common reconnaissance technique.",
             "reconnaissance", "ibm_activity",
             ibm_activity_cfg(service="iam", operation="iam.policy.list")),
        ]
        for args in recon:
            emit(f, *args)
            count += 1

        # ── Execute: IBM Activity ─────────────────────────────────────────
        execute = [
            ("threat.ibm.execute.containers_pod_exec",  "is", "ibm",
             "IBM Containers: Pod Exec Command Executed",
             "An exec command was run inside an IBM Containers Kubernetes pod.",
             "execute", "ibm_activity",
             ibm_activity_cfg(service="containers_kubernetes", operation="containers.pod.exec")),
            ("threat.ibm.execute.function_invoke",      "functions", "ibm",
             "IBM Functions: Action Invoked",
             "An IBM Cloud Functions action was invoked. Review for unauthorized code execution.",
             "execute", "ibm_activity",
             ibm_activity_cfg(service="functions", operation="functions.action.invoke")),
        ]
        for args in execute:
            emit(f, *args)
            count += 1

        # ── Threat (IBM Security): IBM Activity ───────────────────────────
        threat = [
            ("threat.ibm.threat.security_high",     "iam_identity", "ibm",
             "IBM Security: High Severity Finding",
             "IBM Cloud Security detected a high severity security event requiring investigation.",
             "threat", "ibm_activity",
             ibm_activity_cfg(service="security_insights", outcome="failure")),
            ("threat.ibm.threat.kms_key_delete",    "kms", "ibm",
             "IBM KMS: Encryption Key Deleted",
             "An IBM Key Protect encryption key was deleted. Key deletion may cause data inaccessibility.",
             "threat", "ibm_activity",
             ibm_activity_cfg(service="kms", operation="kms.secrets.delete")),
            ("threat.ibm.threat.secrets_delete",    "secrets_manager", "ibm",
             "IBM Secrets Manager: Secret Deleted",
             "A secret was deleted from IBM Secrets Manager. May disrupt applications or indicate data destruction.",
             "threat", "ibm_activity",
             ibm_activity_cfg(service="secrets_manager", operation="secrets-manager.secret.delete")),
        ]
        for args in threat:
            emit(f, *args)
            count += 1

        # ── Exfiltration: IBM Activity ────────────────────────────────────
        exfil = [
            ("threat.ibm.exfiltration.cos_bucket_public", "cloud_object_storage", "ibm",
             "IBM Cloud Object Storage: Bucket ACL Modified",
             "IBM COS bucket access control was modified, potentially exposing data publicly.",
             "exfiltration", "ibm_activity",
             ibm_activity_cfg(service="cloud_object_storage", operation="cloud-object-storage.bucket-acl.set")),
            ("threat.ibm.exfiltration.cos_credentials",   "cloud_object_storage", "ibm",
             "IBM Cloud Object Storage: HMAC Credentials Created",
             "HMAC credentials were created for IBM COS, enabling programmatic storage access.",
             "exfiltration", "ibm_activity",
             ibm_activity_cfg(service="cloud_object_storage", operation="cloud-object-storage.bucket-credentials.create")),
        ]
        for args in exfil:
            emit(f, *args)
            count += 1

        f.write("COMMIT;\n")
    print(f"IBM threat rules: {count} → {path}")
    return count


# ===========================================================================
# Main
# ===========================================================================

if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))

    total = 0
    total += generate_azure(out_dir)
    total += generate_gcp(out_dir)
    total += generate_oci(out_dir)
    total += generate_ibm(out_dir)

    print(f"\nTotal threat detection rules generated: {total}")
    print("Files:")
    print(f"  {out_dir}/ciem_azure_threat_rules.sql")
    print(f"  {out_dir}/ciem_gcp_threat_rules.sql")
    print(f"  {out_dir}/ciem_oci_threat_rules.sql")
    print(f"  {out_dir}/ciem_ibm_threat_rules.sql")
