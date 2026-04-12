#!/usr/bin/env python3
"""
CIEM Threat Rule Expansion — Azure / GCP / OCI / IBM
Adds audit_activity, additional network, execute, c2, authorization,
reconnaissance, and error-monitoring rules to close the gap with AWS coverage.

Run: python generate_ciem_threat_rules_expanded.py
"""

import json, os
from typing import List, Tuple


def sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _cfg(conds: list) -> str:
    return sql_str(json.dumps({"conditions": {"all": conds}}, separators=(',', ':')))


# ── config builders ────────────────────────────────────────────────────────

def az_act(arm_op=None, outcome=None, op_contains=None, service=None):
    c = [{"op": "equals", "field": "source_type", "value": "azure_activity"}]
    if outcome:   c.append({"op": "equals",   "field": "outcome",    "value": outcome})
    if service:   c.append({"op": "equals",   "field": "service",    "value": service})
    if arm_op:    c.append({"op": "equals",   "field": "operation",  "value": arm_op})
    if op_contains and not arm_op:
                  c.append({"op": "contains", "field": "operation",  "value": op_contains})
    return _cfg(c)

def az_nsg(dst_port=None, flow_action=None, dst_ports=None):
    c = [{"op": "equals", "field": "source_type", "value": "azure_nsg_flow"}]
    if flow_action: c.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None: c.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports: c.append({"op": "in", "field": "network.dst_port", "value": [str(p) for p in dst_ports]})
    return _cfg(c)

def az_def(severity=None, op_contains=None):
    c = [{"op": "equals", "field": "source_type", "value": "azure_defender"}]
    if severity:    c.append({"op": "equals",   "field": "severity",   "value": severity})
    if op_contains: c.append({"op": "contains", "field": "operation",  "value": op_contains})
    return _cfg(c)

def az_aks(op_contains):
    return _cfg([
        {"op": "equals",   "field": "source_type", "value": "azure_aks_audit"},
        {"op": "contains", "field": "operation",   "value": op_contains},
    ])

def gcp_aud(svc_uri=None, op_contains=None, outcome=None, exact_op=None):
    c = [{"op": "equals", "field": "source_type", "value": "gcp_audit"}]
    if outcome:   c.append({"op": "equals",   "field": "outcome",   "value": outcome})
    if svc_uri:   c.append({"op": "equals",   "field": "service",   "value": svc_uri})
    if exact_op:  c.append({"op": "contains", "field": "operation", "value": exact_op})
    elif op_contains: c.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(c)

def gcp_flow(dst_port=None, flow_action=None, dst_ports=None):
    c = [{"op": "equals", "field": "source_type", "value": "gcp_vpc_flow"}]
    if flow_action: c.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None: c.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports: c.append({"op": "in", "field": "network.dst_port", "value": [str(p) for p in dst_ports]})
    return _cfg(c)

def gcp_gke(op_contains):
    return _cfg([
        {"op": "equals",   "field": "source_type", "value": "gcp_gke_audit"},
        {"op": "contains", "field": "operation",   "value": op_contains},
    ])

def gcp_scc(severity=None, op_contains=None):
    c = [{"op": "equals", "field": "source_type", "value": "gcp_scc"}]
    if severity:    c.append({"op": "equals",   "field": "severity",   "value": severity})
    if op_contains: c.append({"op": "contains", "field": "operation",  "value": op_contains})
    return _cfg(c)

def oci_aud(cadf=None, op=None, outcome=None, op_contains=None):
    c = [{"op": "equals", "field": "source_type", "value": "oci_audit"}]
    if outcome: c.append({"op": "equals", "field": "outcome",    "value": outcome})
    if cadf:    c.append({"op": "equals", "field": "service",    "value": cadf})
    if op:      c.append({"op": "equals", "field": "operation",  "value": op})
    elif op_contains: c.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(c)

def oci_vcn(dst_port=None, flow_action=None, dst_ports=None):
    c = [{"op": "equals", "field": "source_type", "value": "oci_vcn_flow"}]
    if flow_action: c.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None: c.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports: c.append({"op": "in", "field": "network.dst_port", "value": [str(p) for p in dst_ports]})
    return _cfg(c)

def ibm_act(service=None, op_contains=None, outcome=None, exact_op=None):
    c = [{"op": "equals", "field": "source_type", "value": "ibm_activity"}]
    if outcome: c.append({"op": "equals",   "field": "outcome",   "value": outcome})
    if service: c.append({"op": "equals",   "field": "service",   "value": service})
    if exact_op:  c.append({"op": "contains", "field": "operation", "value": exact_op})
    elif op_contains: c.append({"op": "contains", "field": "operation", "value": op_contains})
    return _cfg(c)

def ibm_vpc(dst_port=None, flow_action=None, dst_ports=None):
    c = [{"op": "equals", "field": "source_type", "value": "ibm_vpc_flow"}]
    if flow_action: c.append({"op": "equals", "field": "network.flow_action", "value": flow_action})
    if dst_port is not None: c.append({"op": "equals", "field": "network.dst_port", "value": str(dst_port)})
    if dst_ports: c.append({"op": "in", "field": "network.dst_port", "value": [str(p) for p in dst_ports]})
    return _cfg(c)


# ── MITRE / severity lookup ────────────────────────────────────────────────

MITRE_MAP = {
    'audit_activity':       ('["discovery","collection"]',               '["T1530","T1087","T1526"]'),
    'privilege_escalation': ('["privilege-escalation"]',                 '["T1078","T1484","T1098"]'),
    'reconnaissance':       ('["reconnaissance","discovery"]',           '["T1595","T1526","T1087"]'),
    'authentication':       ('["initial-access","credential-access"]',   '["T1078","T1110"]'),
    'authorization':        ('["defense-evasion","privilege-escalation"]','["T1098","T1134"]'),
    'execute':              ('["execution"]',                            '["T1059","T1610"]'),
    'network':              ('["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]'),
    'threat':               ('["initial-access","execution"]',           '["T1195","T1059"]'),
    'exfiltration':         ('["exfiltration"]',                         '["T1048","T1537"]'),
    'brute_force':          ('["credential-access"]',                    '["T1110"]'),
    'c2':                   ('["command-and-control"]',                  '["T1071","T1568"]'),
    'malware':              ('["execution","impact"]',                   '["T1204","T1485"]'),
    'cryptomining':         ('["impact"]',                               '["T1496"]'),
    'error':                ('["defense-evasion"]',                      '["T1562"]'),
}

SEV_MAP = {
    'audit_activity':       ('medium',   50),
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
    'error':                ('low',      25),
}


def emit(f, rule_id, service, provider, title, desc, cat, log_src, cfg):
    tactics, techniques = MITRE_MAP.get(cat, ('["persistence"]', '["T1098"]'))
    sev, risk = SEV_MAP.get(cat, ('medium', 55))
    f.write(
        f"INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)\n"
        f"VALUES ({sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},'log',true,{cfg})\n"
        f"ON CONFLICT DO NOTHING;\n\n"
        f"INSERT INTO rule_metadata (\n"
        f"  rule_id,service,provider,severity,title,description,\n"
        f"  domain,subcategory,log_source_type,audit_log_event,action_category,\n"
        f"  rule_source,engines,primary_engine,\n"
        f"  mitre_tactics,mitre_techniques,risk_score,quality,csp\n"
        f") VALUES (\n"
        f"  {sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},\n"
        f"  {sql_str(sev)},{sql_str(title)},{sql_str(desc)},\n"
        f"  'threat_detection',{sql_str(cat)},{sql_str(log_src)},\n"
        f"  {sql_str(log_src+'_'+cat)},{sql_str(cat)},\n"
        f"  'log','{{\"{provider}_ciem\"}}','ciem_engine',\n"
        f"  '{tactics}','{techniques}',{risk},'auto',{sql_str(provider)}\n"
        f") ON CONFLICT DO NOTHING;\n\n"
    )


# ══════════════════════════════════════════════════════════════════════════════
# AZURE
# ══════════════════════════════════════════════════════════════════════════════

OCI_IDENTITY = "com.oraclecloud.identitycontrolplane"
OCI_COMPUTE  = "com.oraclecloud.computeapi"
OCI_VAULT    = "com.oraclecloud.vaultmng"
OCI_NETWORK  = "com.oraclecloud.virtualnetwork"
OCI_BASTION  = "com.oraclecloud.bastion"
OCI_OKE      = "com.oraclecloud.containerengine"
OCI_OBJECT   = "com.oraclecloud.objectstorage"
OCI_BLOCKVOL = "com.oraclecloud.blockstorage"
OCI_DATABASE = "com.oraclecloud.database"
OCI_KEYMANAG = "com.oraclecloud.keymanagement"
OCI_LOGSVC   = "com.oraclecloud.logging"
OCI_AUDIT    = "com.oraclecloud.audit"
OCI_CG       = "com.oraclecloud.cloudguard"


def generate_azure_expanded(out_dir):
    path = os.path.join(out_dir, "ciem_azure_threat_rules_expanded.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- CIEM Azure Threat Detection Rules (Expanded)\nBEGIN;\n\n")

        # ── audit_activity: Key Vault management plane ───────────────────
        kv_audit = [
            ("threat.azure.audit.kv_secret_metadata",    "keyvault",
             "Azure Key Vault: Secret Metadata Read",
             "Key Vault secret names were enumerated. Listing secrets is a reconnaissance precursor to targeted theft.",
             "Microsoft.KeyVault/vaults/secrets/readMetadata/action"),
            ("threat.azure.audit.kv_key_metadata",       "keyvault",
             "Azure Key Vault: Key Metadata Read",
             "Key Vault key names were enumerated.",
             "Microsoft.KeyVault/vaults/keys/readMetadata/action"),
            ("threat.azure.audit.kv_cert_metadata",      "keyvault",
             "Azure Key Vault: Certificate Metadata Read",
             "Key Vault certificate names were enumerated.",
             "Microsoft.KeyVault/vaults/certificates/readMetadata/action"),
            ("threat.azure.audit.kv_deploy_action",      "keyvault",
             "Azure Key Vault: Vault Deployed For Template",
             "A Key Vault was referenced in an ARM template deployment. Keys may be exposed to automated processes.",
             "Microsoft.KeyVault/vaults/deploy/action"),
            ("threat.azure.audit.kv_purge",              "keyvault",
             "Azure Key Vault: Vault Purged (Irreversible Delete)",
             "A soft-deleted Key Vault was permanently purged. All keys, secrets, and certificates are unrecoverable.",
             "Microsoft.KeyVault/vaults/purge/action"),
            ("threat.azure.audit.kv_key_purge",          "keyvault",
             "Azure Key Vault: Key Purged",
             "A soft-deleted Key Vault key was permanently purged.",
             "Microsoft.KeyVault/vaults/keys/purge/action"),
            ("threat.azure.audit.kv_secret_purge",       "keyvault",
             "Azure Key Vault: Secret Purged",
             "A soft-deleted Key Vault secret was permanently purged.",
             "Microsoft.KeyVault/vaults/secrets/purge/action"),
        ]
        for rid, svc, title, desc, arm_op in kv_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Compute sensitive operations ─────────────────
        compute_audit = [
            ("threat.azure.audit.vm_run_command",           "compute",
             "Azure VM: Run Command Executed",
             "A Run Command script was executed inside a VM. This is a remote execution vector equivalent to SSH/WinRM.",
             "Microsoft.Compute/virtualMachines/runCommand/action"),
            ("threat.azure.audit.vm_capture",               "compute",
             "Azure VM: VM Image Captured",
             "A running VM was captured as a generalized image. This can expose sensitive data from disk.",
             "Microsoft.Compute/virtualMachines/capture/action"),
            ("threat.azure.audit.vm_generalize",            "compute",
             "Azure VM: VM Generalized",
             "A VM was generalized (sysprep) — a precursor to capturing disk for potential exfiltration.",
             "Microsoft.Compute/virtualMachines/generalize/action"),
            ("threat.azure.audit.vm_reimage",               "compute",
             "Azure VM: VM Reimaged",
             "A VM was reimaged. This replaces the OS disk and can destroy evidence of compromise.",
             "Microsoft.Compute/virtualMachines/reimage/action"),
            ("threat.azure.audit.vm_redeploy",              "compute",
             "Azure VM: VM Redeployed",
             "A VM was redeployed to a different host. Can be used to disrupt monitoring or evade detection.",
             "Microsoft.Compute/virtualMachines/redeploy/action"),
            ("threat.azure.audit.vm_boot_diagnostics",      "compute",
             "Azure VM: Boot Diagnostics Data Retrieved",
             "Boot diagnostics data (including screenshots and serial output) was retrieved from a VM.",
             "Microsoft.Compute/virtualMachines/retrieveBootDiagnosticsData/action"),
            ("threat.azure.audit.disk_begin_access",        "compute",
             "Azure Disk: Disk Export Access Initiated",
             "Direct disk access was initiated for an Azure managed disk. SAS URIs allow disk content download.",
             "Microsoft.Compute/disks/beginGetAccess/action"),
            ("threat.azure.audit.vm_reset_agent",           "compute",
             "Azure VM: VM Agent Reset",
             "The Azure VM Agent was reset. This can disable monitoring agents and alter VM behavior.",
             "Microsoft.Compute/virtualMachines/resetVMAgent/action"),
            ("threat.azure.audit.vmss_run_command",         "compute",
             "Azure VMSS: Run Command Executed on Scale Set",
             "A Run Command script was executed across a VM Scale Set instance.",
             "Microsoft.Compute/virtualMachineScaleSets/runCommand/action"),
            ("threat.azure.audit.vm_extension_run",         "compute",
             "Azure VM: Custom Script Extension Triggered",
             "A Custom Script Extension executed on a VM. Script extensions can run arbitrary code.",
             "Microsoft.Compute/virtualMachines/runCommand/action"),
        ]
        for rid, svc, title, desc, arm_op in compute_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Storage sensitive ───────────────────────────
        storage_audit = [
            ("threat.azure.audit.storage_regen_key",        "storage",
             "Azure Storage: Account Key Regenerated",
             "A storage account access key was regenerated. Old keys are immediately invalidated, potentially disrupting services.",
             "Microsoft.Storage/storageAccounts/regeneratekey/action"),
            ("threat.azure.audit.storage_delegation_key",   "storage",
             "Azure Storage: User Delegation Key Generated",
             "A user delegation key was generated for Azure Blob Storage. Delegation keys create short-lived SAS tokens.",
             "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"),
            ("threat.azure.audit.storage_sas_account",      "storage",
             "Azure Storage: Account SAS Token Listed",
             "An Account SAS token was listed for a storage account, granting broad access to storage resources.",
             "Microsoft.Storage/storageAccounts/ListAccountSas/action"),
            ("threat.azure.audit.storage_blob_immutability","storage",
             "Azure Storage: Blob Immutability Policy Modified",
             "A blob immutability (WORM) policy was changed, potentially allowing modification of compliance records.",
             "Microsoft.Storage/storageAccounts/blobServices/containers/clearLegalHold/action"),
        ]
        for rid, svc, title, desc, arm_op in storage_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: AKS credential retrieval ────────────────────
        aks_cred = [
            ("threat.azure.audit.aks_admin_creds",          "containerservice",
             "Azure AKS: Cluster Admin Credentials Retrieved",
             "AKS cluster admin credentials were retrieved. Admin kubeconfig grants full cluster access.",
             "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"),
            ("threat.azure.audit.aks_user_creds",           "containerservice",
             "Azure AKS: Cluster User Credentials Retrieved",
             "AKS cluster user credentials were retrieved.",
             "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"),
            ("threat.azure.audit.aks_monitor_creds",        "containerservice",
             "Azure AKS: Cluster Monitoring Credentials Retrieved",
             "AKS cluster monitoring credentials were retrieved. These provide read access to cluster metrics.",
             "Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action"),
            ("threat.azure.audit.aks_upgrade",              "containerservice",
             "Azure AKS: Cluster Kubernetes Version Upgraded",
             "AKS cluster Kubernetes version was upgraded. Forced upgrades can trigger node restarts and monitoring gaps.",
             "Microsoft.ContainerService/managedClusters/upgradeNodeImageVersion/action"),
        ]
        for rid, svc, title, desc, arm_op in aks_cred:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Network sensitive ───────────────────────────
        net_audit = [
            ("threat.azure.audit.net_packet_capture",       "network",
             "Azure Network Watcher: Packet Capture Created",
             "A packet capture session was created in Azure Network Watcher. Captures can intercept network traffic.",
             "Microsoft.Network/networkWatchers/packetCaptures/write"),
            ("threat.azure.audit.net_vnet_peering",         "network",
             "Azure VNet: VNet Peering Created",
             "A new VNet peering was created. Peering connects isolated networks and can bypass security boundaries.",
             "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write"),
            ("threat.azure.audit.net_flow_log",             "network",
             "Azure Network Watcher: Flow Log Updated",
             "A Network Watcher flow log was created or updated. Changes may reduce network visibility.",
             "Microsoft.Network/networkWatchers/flowLogs/write"),
            ("threat.azure.audit.net_vpn_sharedkey",        "network",
             "Azure VPN: VPN Shared Key Retrieved",
             "The shared pre-authentication key for an Azure VPN connection was retrieved.",
             "Microsoft.Network/connections/sharedKey/action"),
            ("threat.azure.audit.net_expressroute_auth",    "network",
             "Azure ExpressRoute: Authorization Key Listed",
             "An ExpressRoute circuit authorization key was listed, providing access to the circuit.",
             "Microsoft.Network/expressRouteCircuits/authorizations/write"),
        ]
        for rid, svc, title, desc, arm_op in net_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Automation / DevOps ─────────────────────────
        auto_audit = [
            ("threat.azure.audit.automation_runbook_write", "automation",
             "Azure Automation: Runbook Created or Modified",
             "An Azure Automation runbook was created or modified. Runbooks execute code on managed systems.",
             "Microsoft.Automation/automationAccounts/runbooks/write"),
            ("threat.azure.audit.automation_job_start",     "automation",
             "Azure Automation: Job Started",
             "An Azure Automation runbook job was started. Jobs execute scripts on Azure infrastructure.",
             "Microsoft.Automation/automationAccounts/jobs/write"),
            ("threat.azure.audit.automation_credential",    "automation",
             "Azure Automation: Credential Asset Modified",
             "An Azure Automation credential asset was created or updated. These store username/password pairs.",
             "Microsoft.Automation/automationAccounts/credentials/write"),
            ("threat.azure.audit.automation_variable",      "automation",
             "Azure Automation: Variable Asset Modified",
             "An Azure Automation variable was written. Variables can store secrets accessible to runbooks.",
             "Microsoft.Automation/automationAccounts/variables/write"),
            ("threat.azure.audit.devops_pipeline_run",      "devtestlab",
             "Azure DevOps: Pipeline Execution",
             "An Azure DevOps pipeline or release was triggered. Pipelines can deploy to production environments.",
             "Microsoft.DevTestLab/labs/write"),
            ("threat.azure.audit.logic_app_trigger",        "logic",
             "Azure Logic App: Workflow Triggered",
             "An Azure Logic App workflow was triggered. Logic Apps can orchestrate actions across services.",
             "Microsoft.Logic/workflows/triggers/run/action"),
        ]
        for rid, svc, title, desc, arm_op in auto_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Security configuration changes ───────────────
        sec_audit = [
            ("threat.azure.audit.security_auto_provision",  "security",
             "Azure Security Center: Auto-Provisioning Settings Changed",
             "Microsoft Defender for Cloud auto-provisioning settings were changed. This controls agent deployment.",
             "Microsoft.Security/autoProvisioningSettings/write"),
            ("threat.azure.audit.security_pricing",         "security",
             "Azure Defender: Plan Pricing Changed",
             "Microsoft Defender for Cloud pricing tier was changed. Downgrades reduce threat detection coverage.",
             "Microsoft.Security/pricings/write"),
            ("threat.azure.audit.security_workspace",       "security",
             "Azure Security Center: Workspace Settings Changed",
             "The Log Analytics workspace for Microsoft Defender for Cloud was changed.",
             "Microsoft.Security/workspaceSettings/write"),
            ("threat.azure.audit.security_contact",         "security",
             "Azure Security Center: Security Contact Deleted",
             "A Microsoft Defender for Cloud security contact was deleted, removing alert notification recipients.",
             "Microsoft.Security/securityContacts/delete"),
            ("threat.azure.audit.diagnostic_delete",        "insights",
             "Azure Monitor: Diagnostic Settings Deleted",
             "Azure Monitor diagnostic settings were deleted. This removes log forwarding to storage/SIEM.",
             "Microsoft.Insights/diagnosticSettings/delete"),
            ("threat.azure.audit.activity_alert_delete",    "insights",
             "Azure Monitor: Activity Log Alert Deleted",
             "An Azure Monitor activity log alert was deleted. Alerts notify on security-relevant events.",
             "Microsoft.Insights/activityLogAlerts/delete"),
            ("threat.azure.audit.log_workspace_delete",     "operationalinsights",
             "Azure Log Analytics: Workspace Deleted",
             "A Log Analytics workspace was deleted. This destroys log retention and SIEM connectivity.",
             "Microsoft.OperationalInsights/workspaces/delete"),
        ]
        for rid, svc, title, desc, arm_op in sec_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── audit_activity: Identity / Service Principal ─────────────────
        id_audit = [
            ("threat.azure.audit.sp_credential_add",        "authorization",
             "Azure: Service Principal Credential Added",
             "A credential (password/certificate) was added to a service principal, creating a new auth secret.",
             "servicePrincipals/credentials"),
            ("threat.azure.audit.app_credential_add",       "authorization",
             "Azure AD: Application Credential Added",
             "A credential was added to an Azure AD application registration, creating a client secret.",
             "applications/credentials"),
            ("threat.azure.audit.subscription_transfer",    "subscription",
             "Azure: Subscription Billing Ownership Transferred",
             "Azure subscription billing ownership was transferred, potentially changing administrative control.",
             "Microsoft.Billing/billingAccounts"),
            ("threat.azure.audit.blueprint_assign",         "blueprint",
             "Azure Blueprints: Blueprint Assigned",
             "An Azure Blueprint was assigned to a subscription. Blueprints can deploy policies, RBACs, and resources.",
             "Microsoft.Blueprint/blueprintAssignments/write"),
        ]
        for rid, svc, title, desc, op_c in id_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(op_contains=op_c))
            n += 1

        # ── audit_activity: Database sensitive ──────────────────────────
        db_audit = [
            ("threat.azure.audit.sql_audit_disable",        "sql",
             "Azure SQL: Auditing Settings Disabled",
             "Azure SQL Server auditing was disabled. This removes logging of database access and changes.",
             "Microsoft.Sql/servers/auditingSettings/write"),
            ("threat.azure.audit.sql_alert_disable",        "sql",
             "Azure SQL: Threat Detection Policy Changed",
             "Azure SQL Server Advanced Threat Protection policy was changed, potentially reducing alerting.",
             "Microsoft.Sql/servers/securityAlertPolicies/write"),
            ("threat.azure.audit.cosmos_key_list",          "documentdb",
             "Azure Cosmos DB: Account Keys Listed",
             "Cosmos DB account keys were listed. These keys provide full database read/write access.",
             "Microsoft.DocumentDB/databaseAccounts/listKeys/action"),
            ("threat.azure.audit.cosmos_conn_strings",      "documentdb",
             "Azure Cosmos DB: Connection Strings Listed",
             "Cosmos DB connection strings were listed. Connection strings contain embedded credentials.",
             "Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action"),
        ]
        for rid, svc, title, desc, arm_op in db_audit:
            emit(f, rid, svc, "azure", title, desc, "audit_activity", "azure_activity",
                 az_act(arm_op=arm_op))
            n += 1

        # ── Network: more NSG port patterns ─────────────────────────────
        more_net = [
            ("threat.azure.network.nsg_telnet_allow",  "nsg_flow", "azure",
             "Azure NSG: Telnet Traffic Allowed (Port 23)",
             "Telnet traffic (port 23) was allowed. Telnet transmits credentials in plaintext.",
             "network", "azure_nsg_flow", az_nsg(dst_port=23, flow_action="A")),
            ("threat.azure.network.nsg_smtp_allow",    "nsg_flow", "azure",
             "Azure NSG: SMTP Traffic Allowed (Port 25)",
             "SMTP traffic (port 25) was allowed. Open SMTP can enable spam relay and data exfiltration.",
             "network", "azure_nsg_flow", az_nsg(dst_port=25, flow_action="A")),
            ("threat.azure.network.nsg_winrm_allow",   "nsg_flow", "azure",
             "Azure NSG: WinRM Traffic Allowed (Ports 5985/5986)",
             "Windows Remote Management traffic was allowed. WinRM enables remote PowerShell execution.",
             "execute", "azure_nsg_flow", az_nsg(dst_ports=[5985, 5986], flow_action="A")),
            ("threat.azure.network.nsg_redis_allow",   "nsg_flow", "azure",
             "Azure NSG: Redis Port Exposed (Port 6379)",
             "Redis traffic (port 6379) was allowed. Exposed Redis instances are frequently compromised.",
             "network", "azure_nsg_flow", az_nsg(dst_port=6379, flow_action="A")),
            ("threat.azure.network.nsg_es_allow",      "nsg_flow", "azure",
             "Azure NSG: Elasticsearch Port Exposed (Port 9200)",
             "Elasticsearch HTTP API (port 9200) was allowed. Exposed ES clusters are a common data breach vector.",
             "network", "azure_nsg_flow", az_nsg(dst_port=9200, flow_action="A")),
            ("threat.azure.network.nsg_memcached_allow","nsg_flow", "azure",
             "Azure NSG: Memcached Port Exposed (Port 11211)",
             "Memcached traffic (port 11211) was allowed. Exposed Memcached is exploited for DDoS amplification.",
             "network", "azure_nsg_flow", az_nsg(dst_port=11211, flow_action="A")),
            ("threat.azure.network.nsg_http_allow",    "nsg_flow", "azure",
             "Azure NSG: HTTP Traffic Allowed (Port 80)",
             "HTTP traffic (port 80) was allowed inbound. Unencrypted HTTP exposes data in transit.",
             "network", "azure_nsg_flow", az_nsg(dst_port=80, flow_action="A")),
            ("threat.azure.network.nsg_https_allow",   "nsg_flow", "azure",
             "Azure NSG: HTTPS Traffic Allowed (Port 443)",
             "HTTPS traffic (port 443) was allowed. Monitor for C2 over HTTPS.",
             "network", "azure_nsg_flow", az_nsg(dst_port=443, flow_action="A")),
            ("threat.azure.network.nsg_telnet_deny",   "nsg_flow", "azure",
             "Azure NSG: Telnet Traffic Blocked",
             "Telnet (port 23) was denied — expected, but high volumes indicate scanning.",
             "network", "azure_nsg_flow", az_nsg(dst_port=23, flow_action="D")),
            ("threat.azure.network.nsg_smb_lateral",   "nsg_flow", "azure",
             "Azure NSG: SMB Lateral Movement Detected",
             "SMB traffic (port 445) between internal hosts was allowed — possible lateral movement.",
             "network", "azure_nsg_flow", az_nsg(dst_ports=[445, 139], flow_action="A")),
        ]
        for args in more_net:
            emit(f, *args)
            n += 1

        # ── Execute: additional ──────────────────────────────────────────
        more_exec = [
            ("threat.azure.execute.vm_runcommand",        "compute", "azure",
             "Azure VM: Run Command Executed via Activity Log",
             "An Azure VM Run Command was executed, allowing arbitrary script execution inside the VM.",
             "execute", "azure_activity", az_act(op_contains="runCommand")),
            ("threat.azure.execute.automation_start",     "automation", "azure",
             "Azure Automation: Runbook Job Started",
             "An Azure Automation runbook job was started, executing code on managed infrastructure.",
             "execute", "azure_activity", az_act(op_contains="automationAccounts/jobs")),
            ("threat.azure.execute.container_create",     "containerinstance", "azure",
             "Azure Container Instance: Container Group Created",
             "A new Azure Container Instance group was created. ACI can execute arbitrary container workloads.",
             "execute", "azure_activity",
             az_act(arm_op="Microsoft.ContainerInstance/containerGroups/write")),
            ("threat.azure.execute.container_exec",       "containerinstance", "azure",
             "Azure Container Instance: Container Exec Session",
             "An exec session was opened in an Azure Container Instance.",
             "execute", "azure_activity", az_act(op_contains="containerGroups/containers/exec")),
            ("threat.azure.execute.function_key_list",    "web", "azure",
             "Azure Function: Function Keys Listed",
             "Azure Function API keys were listed. These keys authenticate function invocations.",
             "execute", "azure_activity", az_act(op_contains="sites/functions/keys")),
            ("threat.azure.execute.aks_node_drain",       "containerservice", "azure",
             "Azure AKS: Node Pool Drained",
             "An AKS node pool was drained, removing all pods from nodes and potentially disrupting workloads.",
             "execute", "azure_activity", az_act(op_contains="managedClusters/agentPools")),
        ]
        for args in more_exec:
            emit(f, *args)
            n += 1

        # ── C2 / Malware: Defender extended ─────────────────────────────
        c2_ext = [
            ("threat.azure.c2.defender_c2_channel",    "defender", "azure",
             "Azure Defender: C2 Communication Channel Detected",
             "Microsoft Defender for Cloud detected a potential command-and-control communication channel.",
             "c2", "azure_defender", az_def(op_contains="CommandAndControl")),
            ("threat.azure.c2.defender_reverse_shell", "defender", "azure",
             "Azure Defender: Reverse Shell Activity Detected",
             "Microsoft Defender for Cloud detected possible reverse shell or interactive shell activity.",
             "c2", "azure_defender", az_def(op_contains="ReverseShell")),
            ("threat.azure.malware.defender_ransomware","defender", "azure",
             "Azure Defender: Ransomware Activity Detected",
             "Microsoft Defender for Cloud detected ransomware-like behavior on an Azure resource.",
             "malware", "azure_defender", az_def(op_contains="Ransomware")),
            ("threat.azure.cryptomining.defender_crypto","defender", "azure",
             "Azure Defender: Cryptomining Activity Detected",
             "Microsoft Defender for Cloud detected cryptomining workloads on an Azure resource.",
             "cryptomining", "azure_defender", az_def(op_contains="CryptoMining")),
        ]
        for args in c2_ext:
            emit(f, *args)
            n += 1

        # ── Authorization failures ───────────────────────────────────────
        authz = [
            ("threat.azure.authorization.storage_denied",   "storage", "azure",
             "Azure Storage: Authorization Failure",
             "Access to an Azure Storage resource was denied. Repeated denials may indicate unauthorized access attempts.",
             "authorization", "azure_activity", az_act(service="storage", outcome="failure")),
            ("threat.azure.authorization.sql_denied",        "sql", "azure",
             "Azure SQL: Authorization Failure",
             "Access to an Azure SQL resource was denied.",
             "authorization", "azure_activity", az_act(service="sql", outcome="failure")),
            ("threat.azure.authorization.keyvault_denied",   "keyvault", "azure",
             "Azure Key Vault: Authorization Failure",
             "Access to a Key Vault resource was denied. This may indicate unauthorized access to secrets.",
             "authorization", "azure_activity", az_act(service="keyvault", outcome="failure")),
            ("threat.azure.authorization.containerservice_denied", "containerservice", "azure",
             "Azure AKS: Authorization Failure",
             "An AKS resource operation was denied. May indicate privilege escalation attempt.",
             "authorization", "azure_activity", az_act(service="containerservice", outcome="failure")),
        ]
        for args in authz:
            emit(f, *args)
            n += 1

        # ── Error detection ──────────────────────────────────────────────
        errors = [
            ("threat.azure.error.defender_config_error",  "security", "azure",
             "Azure Defender: Security Configuration Error",
             "A security configuration error was detected in Microsoft Defender for Cloud.",
             "error", "azure_defender", az_def(severity="Informational")),
        ]
        for args in errors:
            emit(f, *args)
            n += 1

        f.write("COMMIT;\n")
    print(f"Azure expanded: {n} → {path}")
    return n


# ══════════════════════════════════════════════════════════════════════════════
# GCP
# ══════════════════════════════════════════════════════════════════════════════

def generate_gcp_expanded(out_dir):
    path = os.path.join(out_dir, "ciem_gcp_threat_rules_expanded.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- CIEM GCP Threat Detection Rules (Expanded)\nBEGIN;\n\n")

        # ── audit_activity: IAM / service accounts ───────────────────────
        iam_audit = [
            ("threat.gcp.audit.sa_generate_id_token",    "iam",
             "GCP IAM: Service Account ID Token Generated",
             "An ID token was generated for a service account, enabling impersonation of the SA identity.",
             "iamcredentials.googleapis.com", "GenerateIdToken"),
            ("threat.gcp.audit.sa_sign_blob",            "iam",
             "GCP IAM: Service Account Blob Signed",
             "A data blob was signed using a service account key, enabling service account impersonation flows.",
             "iamcredentials.googleapis.com", "SignBlob"),
            ("threat.gcp.audit.sa_sign_jwt",             "iam",
             "GCP IAM: Service Account JWT Signed",
             "A JWT was signed using a service account — can be used for API impersonation.",
             "iamcredentials.googleapis.com", "SignJwt"),
            ("threat.gcp.audit.iam_get_policy",          "iam",
             "GCP IAM: IAM Policy Retrieved",
             "An IAM policy was read from a GCP resource. Mass policy enumeration indicates IAM reconnaissance.",
             "iam.googleapis.com", "GetIamPolicy"),
            ("threat.gcp.audit.sa_list",                 "iam",
             "GCP IAM: Service Accounts Listed",
             "Service accounts were listed for a project. Enumeration of SAs is a common privilege escalation precursor.",
             "iam.googleapis.com", "ListServiceAccounts"),
            ("threat.gcp.audit.sa_key_list",             "iam",
             "GCP IAM: Service Account Keys Listed",
             "Keys for a service account were listed. Key enumeration may indicate credential harvesting.",
             "iam.googleapis.com", "ListServiceAccountKeys"),
            ("threat.gcp.audit.roles_list",              "iam",
             "GCP IAM: IAM Roles Listed",
             "Custom or predefined IAM roles were listed. Role enumeration is a common reconnaissance technique.",
             "iam.googleapis.com", "ListRoles"),
            ("threat.gcp.audit.workload_pool_create",    "iam",
             "GCP IAM: Workload Identity Pool Created",
             "A Workload Identity Pool was created, enabling external identities to authenticate as GCP service accounts.",
             "iam.googleapis.com", "CreateWorkloadIdentityPool"),
        ]
        for rid, svc, title, desc, svc_uri, method in iam_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: KMS ──────────────────────────────────────────
        kms_audit = [
            ("threat.gcp.audit.kms_decrypt",             "cloudkms",
             "GCP KMS: Data Decrypted Using KMS Key",
             "Data was decrypted using a Cloud KMS key. Decrypt operations indicate access to encrypted data.",
             "cloudkms.googleapis.com", "Decrypt"),
            ("threat.gcp.audit.kms_get_key",             "cloudkms",
             "GCP KMS: KMS Crypto Key Retrieved",
             "KMS key metadata was retrieved. Key enumeration may precede key extraction or misuse.",
             "cloudkms.googleapis.com", "GetCryptoKey"),
            ("threat.gcp.audit.kms_key_schedule_destroy","cloudkms",
             "GCP KMS: Key Version Scheduled for Destruction",
             "A KMS key version was scheduled for destruction. Key deletion causes permanent data loss.",
             "cloudkms.googleapis.com", "ScheduleDestroyCryptoKeyVersion"),
            ("threat.gcp.audit.kms_set_iam_policy",      "cloudkms",
             "GCP KMS: KMS Key IAM Policy Modified",
             "The IAM policy on a KMS key was changed. Unauthorized modifications grant key access.",
             "cloudkms.googleapis.com", "SetIamPolicy"),
        ]
        for rid, svc, title, desc, svc_uri, method in kms_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: Storage ──────────────────────────────────────
        storage_audit = [
            ("threat.gcp.audit.storage_get_iam",         "storage",
             "GCP Storage: Bucket IAM Policy Retrieved",
             "The IAM policy for a Cloud Storage bucket was retrieved — common reconnaissance before privilege escalation.",
             "storage.googleapis.com", "GetIamPolicy"),
            ("threat.gcp.audit.storage_patch_bucket",    "storage",
             "GCP Storage: Bucket Metadata Updated",
             "Cloud Storage bucket metadata was updated. Changes can affect access controls and versioning.",
             "storage.googleapis.com", "storage.buckets.patch"),
            ("threat.gcp.audit.storage_hmac_key",        "storage",
             "GCP Storage: HMAC Key Created",
             "An HMAC key was created for Cloud Storage. HMAC keys provide service-account-level access via S3 API.",
             "storage.googleapis.com", "CreateHmacKey"),
            ("threat.gcp.audit.storage_unlock_bucket",   "storage",
             "GCP Storage: Retention Policy Unlocked",
             "A storage bucket retention policy lock was removed, allowing object deletion that was previously prohibited.",
             "storage.googleapis.com", "LockRetentionPolicy"),
        ]
        for rid, svc, title, desc, svc_uri, method in storage_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: Compute ──────────────────────────────────────
        compute_audit = [
            ("threat.gcp.audit.compute_set_metadata",       "compute",
             "GCP Compute: Instance Metadata Updated (SSH Keys)",
             "Instance metadata was updated on a GCP VM. Metadata changes can add SSH public keys for unauthorized access.",
             "compute.googleapis.com", "SetMetadata"),
            ("threat.gcp.audit.compute_common_metadata",    "compute",
             "GCP Compute: Project-Wide SSH Keys Updated",
             "Project-wide common instance metadata was changed. This can add SSH keys that apply to ALL project VMs.",
             "compute.googleapis.com", "SetCommonInstanceMetadata"),
            ("threat.gcp.audit.compute_serial_port",        "compute",
             "GCP Compute: Serial Port Output Retrieved",
             "VM serial port output was retrieved. Serial port output may contain sensitive boot and runtime data.",
             "compute.googleapis.com", "GetSerialPortOutput"),
            ("threat.gcp.audit.compute_snapshot_export",    "compute",
             "GCP Compute: Disk Snapshot Created",
             "A persistent disk snapshot was created. Snapshots can be used to exfiltrate disk contents.",
             "compute.googleapis.com", "compute.snapshots.insert"),
            ("threat.gcp.audit.compute_image_iam",          "compute",
             "GCP Compute: Image IAM Policy Set",
             "The IAM policy on a Compute image was changed. Unauthorized sharing exposes image contents.",
             "compute.googleapis.com", "compute.images.setIamPolicy"),
            ("threat.gcp.audit.compute_firewall_disable",   "compute",
             "GCP Compute: Firewall Rule Disabled",
             "A GCP VPC firewall rule was disabled or deleted. This opens network access that was previously blocked.",
             "compute.googleapis.com", "compute.firewalls.delete"),
            ("threat.gcp.audit.compute_add_access_config",  "compute",
             "GCP Compute: External IP Attached to VM",
             "An access config (external IP) was added to a GCP VM instance, exposing it to the internet.",
             "compute.googleapis.com", "AddAccessConfig"),
        ]
        for rid, svc, title, desc, svc_uri, method in compute_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: GKE ─────────────────────────────────────────
        gke_audit = [
            ("threat.gcp.audit.gke_rotate_credentials",  "container",
             "GCP GKE: Cluster Credentials Rotated",
             "GKE cluster credentials were rotated. Improper rotation can disrupt workloads and authentication.",
             "container.googleapis.com", "RotateClusterCredentials"),
            ("threat.gcp.audit.gke_set_master_auth",     "container",
             "GCP GKE: GKE Master Authentication Modified",
             "GKE master authentication configuration was changed. This controls how the cluster API server is accessed.",
             "container.googleapis.com", "SetMasterAuth"),
            ("threat.gcp.audit.gke_set_network_policy",  "container",
             "GCP GKE: GKE Network Policy Changed",
             "GKE cluster network policy was changed. Disabling network policy allows unrestricted pod-to-pod communication.",
             "container.googleapis.com", "SetNetworkPolicy"),
            ("threat.gcp.audit.gke_privileged_node",     "container",
             "GCP GKE: Node Pool with Privileged Containers",
             "A GKE node pool was created with settings that may allow privileged container workloads.",
             "container.googleapis.com", "CreateNodePool"),
        ]
        for rid, svc, title, desc, svc_uri, method in gke_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: Logging / monitoring ────────────────────────
        log_audit = [
            ("threat.gcp.audit.logging_delete_sink",     "logging",
             "GCP Logging: Log Sink Deleted",
             "A Cloud Logging export sink was deleted. This removes log forwarding to SIEM/storage.",
             "logging.googleapis.com", "DeleteSink"),
            ("threat.gcp.audit.logging_update_bucket",   "logging",
             "GCP Logging: Log Bucket Retention Changed",
             "A Cloud Logging log bucket retention period was changed, potentially reducing log availability.",
             "logging.googleapis.com", "UpdateBucket"),
            ("threat.gcp.audit.logging_create_exclusion","logging",
             "GCP Logging: Log Exclusion Created",
             "A Cloud Logging exclusion filter was created. Exclusions prevent specific logs from being ingested.",
             "logging.googleapis.com", "CreateExclusion"),
            ("threat.gcp.audit.logging_delete_log",      "logging",
             "GCP Logging: Log Entries Deleted",
             "Log entries were deleted from Cloud Logging. Log deletion removes audit trail evidence.",
             "logging.googleapis.com", "DeleteLog"),
            ("threat.gcp.audit.monitoring_alert_delete", "monitoring",
             "GCP Monitoring: Alert Policy Deleted",
             "A Cloud Monitoring alert policy was deleted, removing alerting for security-relevant metrics.",
             "monitoring.googleapis.com", "DeleteAlertPolicy"),
        ]
        for rid, svc, title, desc, svc_uri, method in log_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: BigQuery / Spanner / databases ──────────────
        data_audit = [
            ("threat.gcp.audit.bq_table_iam",            "bigquery",
             "GCP BigQuery: Table IAM Policy Modified",
             "The IAM policy on a BigQuery table was changed, potentially exposing sensitive data.",
             "bigquery.googleapis.com", "SetIamPolicy"),
            ("threat.gcp.audit.bq_data_extract",         "bigquery",
             "GCP BigQuery: Data Exported to Storage",
             "A BigQuery data export job was created. Large-scale exports can indicate data exfiltration.",
             "bigquery.googleapis.com", "jobservice.insert"),
            ("threat.gcp.audit.cloudsql_export",         "sqladmin",
             "GCP Cloud SQL: Database Exported",
             "A Cloud SQL database was exported to Cloud Storage. Exports contain full database contents.",
             "sqladmin.googleapis.com", "SqlInstancesExport"),
            ("threat.gcp.audit.cloudsql_user_create",    "sqladmin",
             "GCP Cloud SQL: Database User Created",
             "A new database user was created in a Cloud SQL instance.",
             "sqladmin.googleapis.com", "SqlUsersInsert"),
            ("threat.gcp.audit.cloudsql_ssl_create",     "sqladmin",
             "GCP Cloud SQL: SSL Certificate Created",
             "An SSL certificate was created for a Cloud SQL instance, providing a new authentication credential.",
             "sqladmin.googleapis.com", "SqlSslCertsInsert"),
            ("threat.gcp.audit.spanner_db_drop",         "spanner",
             "GCP Spanner: Database Dropped",
             "A Spanner database was dropped. This is an irreversible operation destroying all data.",
             "spanner.googleapis.com", "DropDatabase"),
        ]
        for rid, svc, title, desc, svc_uri, method in data_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── audit_activity: Secret Manager ──────────────────────────────
        sec_audit = [
            ("threat.gcp.audit.secret_version_add",      "secretmanager",
             "GCP Secret Manager: New Secret Version Added",
             "A new version was added to a Secret Manager secret. New versions may contain rotated credentials.",
             "secretmanager.googleapis.com", "AddSecretVersion"),
            ("threat.gcp.audit.secret_list",             "secretmanager",
             "GCP Secret Manager: Secrets Listed",
             "All secrets in a project were listed. Enumeration of secret names is a reconnaissance technique.",
             "secretmanager.googleapis.com", "ListSecrets"),
            ("threat.gcp.audit.secret_iam_modify",       "secretmanager",
             "GCP Secret Manager: Secret IAM Policy Modified",
             "The IAM policy on a Secret Manager secret was changed, potentially granting unauthorized access.",
             "secretmanager.googleapis.com", "SetIamPolicy"),
        ]
        for rid, svc, title, desc, svc_uri, method in sec_audit:
            emit(f, rid, svc, "gcp", title, desc, "audit_activity", "gcp_audit",
                 gcp_aud(svc_uri=svc_uri, exact_op=method))
            n += 1

        # ── Network: more GCP VPC port patterns ─────────────────────────
        more_net = [
            ("threat.gcp.network.vpc_telnet_allow",   "vpc_flow", "gcp",
             "GCP VPC: Telnet Traffic Allowed (Port 23)",
             "Telnet (port 23) was allowed through GCP VPC firewall. Plaintext protocol exposing credentials.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=23, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_smtp_allow",     "vpc_flow", "gcp",
             "GCP VPC: SMTP Traffic Allowed (Port 25)",
             "SMTP traffic (port 25) allowed. Open relays can enable spam and data exfiltration.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=25, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_winrm_allow",    "vpc_flow", "gcp",
             "GCP VPC: WinRM Traffic Allowed (Ports 5985/5986)",
             "WinRM traffic allowed. Enables remote PowerShell execution on Windows instances.",
             "execute", "gcp_vpc_flow", gcp_flow(dst_ports=[5985, 5986], flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_redis_allow",    "vpc_flow", "gcp",
             "GCP VPC: Redis Port Exposed (Port 6379)",
             "Redis (port 6379) was allowed. Unauthenticated Redis access leads to RCE.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=6379, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_es_allow",       "vpc_flow", "gcp",
             "GCP VPC: Elasticsearch Port Exposed (Port 9200)",
             "Elasticsearch HTTP (port 9200) was allowed. Exposed ES is a common data breach vector.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=9200, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_memcached_allow","vpc_flow", "gcp",
             "GCP VPC: Memcached Port Exposed (Port 11211)",
             "Memcached (port 11211) was allowed. Exploited for reflection DDoS and cache poisoning.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=11211, flow_action="ALLOWED")),
            ("threat.gcp.network.vpc_telnet_denied",  "vpc_flow", "gcp",
             "GCP VPC: Telnet Traffic Blocked",
             "Telnet traffic (port 23) was denied by GCP VPC firewall.",
             "network", "gcp_vpc_flow", gcp_flow(dst_port=23, flow_action="DENIED")),
        ]
        for args in more_net:
            emit(f, *args)
            n += 1

        # ── GKE Execute (additional) ─────────────────────────────────────
        gke_exec = [
            ("threat.gcp.execute.gke_cluster_admin",  "container", "gcp",
             "GCP GKE: Cluster-Admin Role Binding Created",
             "A cluster-admin RBAC binding was created in GKE, granting full cluster control.",
             "execute", "gcp_gke_audit", gcp_gke("clusterrolebindings")),
            ("threat.gcp.execute.gke_privileged_pod", "container", "gcp",
             "GCP GKE: Privileged Pod Created",
             "A privileged pod was created in GKE. Privileged containers can escape to the underlying node.",
             "execute", "gcp_gke_audit", gcp_gke("securityContext")),
        ]
        for args in gke_exec:
            emit(f, *args)
            n += 1

        # ── Authorization / reconnaissance failures ──────────────────────
        authz = [
            ("threat.gcp.authorization.kms_denied",   "cloudkms", "gcp",
             "GCP KMS: Unauthorized KMS Operation",
             "An unauthorized KMS key operation was denied. May indicate lateral movement or key extraction.",
             "authorization", "gcp_audit", gcp_aud(svc_uri="cloudkms.googleapis.com", outcome="failure")),
            ("threat.gcp.authorization.bigquery_denied","bigquery","gcp",
             "GCP BigQuery: Unauthorized Data Access",
             "An unauthorized BigQuery data access was denied. May indicate data exfiltration attempt.",
             "authorization", "gcp_audit", gcp_aud(svc_uri="bigquery.googleapis.com", outcome="failure")),
            ("threat.gcp.authorization.spanner_denied","spanner", "gcp",
             "GCP Spanner: Unauthorized Access",
             "An unauthorized Spanner operation was denied.",
             "authorization", "gcp_audit", gcp_aud(svc_uri="spanner.googleapis.com", outcome="failure")),
            ("threat.gcp.authorization.secretmanager_denied","secretmanager","gcp",
             "GCP Secret Manager: Unauthorized Secret Access",
             "An unauthorized Secret Manager operation was denied. Repeated attempts indicate secret harvesting.",
             "authorization", "gcp_audit", gcp_aud(svc_uri="secretmanager.googleapis.com", outcome="failure")),
        ]
        for args in authz:
            emit(f, *args)
            n += 1

        f.write("COMMIT;\n")
    print(f"GCP expanded: {n} → {path}")
    return n


# ══════════════════════════════════════════════════════════════════════════════
# OCI
# ══════════════════════════════════════════════════════════════════════════════

def generate_oci_expanded(out_dir):
    path = os.path.join(out_dir, "ciem_oci_threat_rules_expanded.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- CIEM OCI Threat Detection Rules (Expanded)\nBEGIN;\n\n")

        # ── audit_activity: Identity ─────────────────────────────────────
        id_audit = [
            ("threat.oci.audit.list_api_keys",         "identity",
             "OCI IAM: API Keys Listed",
             "API signing keys for an OCI user were listed. Key enumeration may precede targeted credential theft.",
             OCI_IDENTITY, "ListApiKeys"),
            ("threat.oci.audit.get_tenancy",           "identity",
             "OCI IAM: Tenancy Information Retrieved",
             "OCI tenancy information was retrieved. Tenancy details can be used for reconnaissance.",
             OCI_IDENTITY, "GetTenancy"),
            ("threat.oci.audit.list_identity_providers","identity",
             "OCI IAM: Identity Providers Listed",
             "Identity providers (SAML/SCIM) were listed. Federation config reveals auth infrastructure.",
             OCI_IDENTITY, "ListIdentityProviders"),
            ("threat.oci.audit.update_tenancy",        "identity",
             "OCI IAM: Tenancy Updated",
             "OCI tenancy settings were updated — high-impact change affecting the entire cloud environment.",
             OCI_IDENTITY, "UpdateTenancy"),
            ("threat.oci.audit.list_dynamic_groups",   "identity",
             "OCI IAM: Dynamic Groups Listed",
             "Dynamic groups were listed. These grant IAM permissions to OCI resources based on matching rules.",
             OCI_IDENTITY, "ListDynamicGroups"),
            ("threat.oci.audit.password_policy_update","identity",
             "OCI IAM: Password Policy Updated",
             "The OCI tenancy password policy was updated. Weakening the policy reduces authentication security.",
             OCI_IDENTITY, "UpdateAuthenticationPolicy"),
            ("threat.oci.audit.mfa_totp_remove",       "identity",
             "OCI IAM: MFA Device Removed",
             "A TOTP (MFA) device was removed from an OCI user account, weakening account security.",
             OCI_IDENTITY, "DeleteMfaTotpDevice"),
        ]
        for rid, svc, title, desc, cadf, op in id_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── audit_activity: Compute ──────────────────────────────────────
        comp_audit = [
            ("threat.oci.audit.get_windows_creds",       "compute",
             "OCI Compute: Windows Initial Credentials Retrieved",
             "Windows instance initial credentials (password) were retrieved. Contains admin password.",
             OCI_COMPUTE, "GetWindowsInstanceInitialCredentials"),
            ("threat.oci.audit.get_console_history",     "compute",
             "OCI Compute: Console History Retrieved",
             "Instance serial console history was retrieved. Console output may contain sensitive startup data.",
             OCI_COMPUTE, "GetConsoleHistory"),
            ("threat.oci.audit.capture_console_history", "compute",
             "OCI Compute: Console History Captured",
             "A new console history capture was initiated for an OCI instance.",
             OCI_COMPUTE, "CaptureConsoleHistory"),
            ("threat.oci.audit.instance_action",         "compute",
             "OCI Compute: Instance Action Triggered",
             "A power action (START/STOP/RESET/SOFTSTOP) was triggered on an OCI instance.",
             OCI_COMPUTE, "InstanceAction"),
        ]
        for rid, svc, title, desc, cadf, op in comp_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── audit_activity: KMS / Vault ──────────────────────────────────
        kms_audit = [
            ("threat.oci.audit.kms_decrypt",           "keymanagement",
             "OCI KMS: Data Decrypted Using KMS Key",
             "Data was decrypted using an OCI KMS key. Decrypt operations indicate access to encrypted data.",
             OCI_KEYMANAG, "Decrypt"),
            ("threat.oci.audit.kms_list_keys",         "keymanagement",
             "OCI KMS: Keys Listed",
             "KMS encryption keys were listed. Key enumeration precedes targeted key access.",
             OCI_KEYMANAG, "ListKeys"),
            ("threat.oci.audit.vault_list_secrets",    "vault",
             "OCI Vault: Secrets Listed",
             "Secrets in the OCI Vault were listed. Secret name enumeration is a reconnaissance technique.",
             OCI_VAULT, "ListSecrets"),
            ("threat.oci.audit.vault_get_secret",      "vault",
             "OCI Vault: Secret Bundle Retrieved",
             "A secret value (bundle) was retrieved from OCI Vault. Review who accessed what secret.",
             OCI_VAULT, "GetSecretBundle"),
        ]
        for rid, svc, title, desc, cadf, op in kms_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── audit_activity: Database ─────────────────────────────────────
        db_audit = [
            ("threat.oci.audit.adb_generate_wallet",   "database",
             "OCI Autonomous DB: Wallet (Credentials) Generated",
             "A database wallet was generated for an Autonomous Database. Wallets contain connection credentials.",
             OCI_DATABASE, "GenerateAutonomousDatabaseWallet"),
            ("threat.oci.audit.db_export",             "database",
             "OCI Database: Data Pump Export Initiated",
             "A Data Pump export was initiated from an OCI database. Exports contain full database contents.",
             OCI_DATABASE, "CreateExadataInfrastructure"),
            ("threat.oci.audit.db_backup_export",      "database",
             "OCI Database: Backup Exported",
             "An OCI database backup was created or exported, enabling offline access to all data.",
             OCI_DATABASE, "CreateBackup"),
        ]
        for rid, svc, title, desc, cadf, op in db_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── audit_activity: Logging / Audit ──────────────────────────────
        log_audit = [
            ("threat.oci.audit.audit_config_update",   "audit",
             "OCI Audit: Audit Configuration Updated",
             "OCI Audit service configuration was updated. Changes may alter retention or event collection.",
             OCI_AUDIT, "UpdateConfiguration"),
            ("threat.oci.audit.log_group_delete",      "logging",
             "OCI Logging: Log Group Deleted",
             "A log group was deleted from OCI Logging. Log deletion removes audit trail evidence.",
             OCI_LOGSVC, "DeleteLogGroup"),
            ("threat.oci.audit.log_delete",            "logging",
             "OCI Logging: Log Deleted",
             "A log resource was deleted from OCI Logging, removing security event history.",
             OCI_LOGSVC, "DeleteLog"),
        ]
        for rid, svc, title, desc, cadf, op in log_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── audit_activity: OKE / Networking ────────────────────────────
        oke_audit = [
            ("threat.oci.audit.oke_get_kubeconfig",    "containerengine",
             "OCI OKE: Kubernetes Kubeconfig Retrieved",
             "A kubeconfig was generated for an OKE cluster. Kubeconfigs grant direct cluster API access.",
             OCI_OKE, "CreateKubeconfig"),
            ("threat.oci.audit.vcn_route_update",      "network",
             "OCI VCN: Route Table Updated",
             "A VCN route table was updated. Unauthorized route changes can redirect traffic for interception.",
             OCI_NETWORK, "UpdateRouteTable"),
            ("threat.oci.audit.vcn_security_list_update","network",
             "OCI VCN: Security List Updated",
             "A VCN security list was updated. Changes can open or close network access unexpectedly.",
             OCI_NETWORK, "UpdateSecurityList"),
            ("threat.oci.audit.vcn_nsg_rules_update",  "network",
             "OCI VCN: NSG Security Rules Updated",
             "Network Security Group rules were updated for an OCI VCN.",
             OCI_NETWORK, "UpdateNetworkSecurityGroupSecurityRules"),
        ]
        for rid, svc, title, desc, cadf, op in oke_audit:
            emit(f, rid, svc, "oci", title, desc, "audit_activity", "oci_audit",
                 oci_aud(cadf=cadf, op=op))
            n += 1

        # ── Network: more OCI VCN port patterns ─────────────────────────
        more_net = [
            ("threat.oci.network.vcn_telnet_accept",  "vcn_flow", "oci",
             "OCI VCN: Telnet Traffic Allowed (Port 23)",
             "Telnet (port 23) was allowed through OCI VCN. Plaintext protocol exposing credentials.",
             "network", "oci_vcn_flow", oci_vcn(dst_port=23, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_winrm_accept",   "vcn_flow", "oci",
             "OCI VCN: WinRM Traffic Allowed (Ports 5985/5986)",
             "WinRM traffic allowed through OCI VCN. Enables remote PowerShell execution.",
             "execute", "oci_vcn_flow", oci_vcn(dst_ports=[5985, 5986], flow_action="ACCEPT")),
            ("threat.oci.network.vcn_redis_accept",   "vcn_flow", "oci",
             "OCI VCN: Redis Port Exposed (Port 6379)",
             "Redis (port 6379) was allowed. Unauthenticated Redis leads to RCE.",
             "network", "oci_vcn_flow", oci_vcn(dst_port=6379, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_smtp_accept",    "vcn_flow", "oci",
             "OCI VCN: SMTP Traffic Allowed (Port 25)",
             "SMTP (port 25) was allowed through OCI VCN. Open relays enable data exfiltration.",
             "network", "oci_vcn_flow", oci_vcn(dst_port=25, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_http_allow",     "vcn_flow", "oci",
             "OCI VCN: HTTP Traffic Allowed (Port 80)",
             "HTTP (port 80) was allowed. Unencrypted traffic exposes data in transit.",
             "network", "oci_vcn_flow", oci_vcn(dst_port=80, flow_action="ACCEPT")),
            ("threat.oci.network.vcn_telnet_reject",  "vcn_flow", "oci",
             "OCI VCN: Telnet Blocked",
             "Telnet (port 23) was rejected. High volumes indicate scanning.",
             "network", "oci_vcn_flow", oci_vcn(dst_port=23, flow_action="REJECT")),
        ]
        for args in more_net:
            emit(f, *args)
            n += 1

        # ── Authorization failures ───────────────────────────────────────
        authz = [
            ("threat.oci.authorization.vault_denied",  "vault", "oci",
             "OCI Vault: Unauthorized Vault Operation",
             "An unauthorized Vault operation was denied. May indicate credential theft attempt.",
             "authorization", "oci_audit", oci_aud(cadf=OCI_VAULT, outcome="failure")),
            ("threat.oci.authorization.kms_denied",    "keymanagement", "oci",
             "OCI KMS: Unauthorized KMS Operation",
             "An unauthorized KMS operation was denied. May indicate key extraction attempt.",
             "authorization", "oci_audit", oci_aud(cadf=OCI_KEYMANAG, outcome="failure")),
            ("threat.oci.authorization.object_denied", "objectstorage", "oci",
             "OCI Object Storage: Unauthorized Access",
             "An unauthorized Object Storage operation was denied.",
             "authorization", "oci_audit",
             oci_aud(cadf="com.oraclecloud.objectstorage", outcome="failure")),
        ]
        for args in authz:
            emit(f, *args)
            n += 1

        f.write("COMMIT;\n")
    print(f"OCI expanded: {n} → {path}")
    return n


# ══════════════════════════════════════════════════════════════════════════════
# IBM
# ══════════════════════════════════════════════════════════════════════════════

def generate_ibm_expanded(out_dir):
    path = os.path.join(out_dir, "ciem_ibm_threat_rules_expanded.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- CIEM IBM Threat Detection Rules (Expanded)\nBEGIN;\n\n")

        # ── audit_activity: IAM Identity ─────────────────────────────────
        iam_audit = [
            ("threat.ibm.audit.list_api_keys",          "iam_identity",
             "IBM IAM: API Keys Listed",
             "IBM IAM API keys were listed. Key enumeration may precede targeted credential theft.",
             "iam_identity", "iam-identity.account.apikey"),
            ("threat.ibm.audit.list_service_ids",       "iam_identity",
             "IBM IAM: Service IDs Listed",
             "IBM Service IDs were listed. Service ID enumeration reveals programmatic access identities.",
             "iam_identity", "iam-identity.serviceid.list"),
            ("threat.ibm.audit.get_service_id",         "iam_identity",
             "IBM IAM: Service ID Retrieved",
             "An IBM Service ID was read. Service IDs are used for programmatic API authentication.",
             "iam_identity", "iam-identity.serviceid.get"),
            ("threat.ibm.audit.list_trusted_profiles",  "iam_identity",
             "IBM IAM: Trusted Profiles Listed",
             "IBM Trusted Profiles were listed. Trusted profiles grant compute resources access to cloud services.",
             "iam_identity", "iam-identity.profile.list"),
            ("threat.ibm.audit.api_key_lock",           "iam_identity",
             "IBM IAM: API Key Locked",
             "An IBM IAM API key was locked. Locking prevents the key from being used for authentication.",
             "iam_identity", "iam-identity.apikey.lock"),
            ("threat.ibm.audit.mfa_update",             "iam_identity",
             "IBM IAM: MFA Settings Updated",
             "IBM IAM MFA (multi-factor authentication) settings were updated. Weakening MFA reduces account security.",
             "iam_identity", "iam-identity.mfa-enrollment.set"),
        ]
        for rid, svc, title, desc, ibm_svc, op in iam_audit:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── audit_activity: IAM Access Management ────────────────────────
        iam_access = [
            ("threat.ibm.audit.list_policies",          "iam",
             "IBM IAM: Access Policies Listed",
             "IBM IAM access policies were listed. Policy enumeration reveals what actions identities can perform.",
             "iam", "iam.policy.list"),
            ("threat.ibm.audit.get_policy",             "iam",
             "IBM IAM: Access Policy Retrieved",
             "An IBM IAM access policy was read.",
             "iam", "iam.policy.get"),
            ("threat.ibm.audit.access_group_list",      "iam",
             "IBM IAM: Access Groups Listed",
             "IBM IAM Access Groups were listed. Access groups aggregate users and service IDs sharing policies.",
             "iam_groups", "iam.access-group.list"),
            ("threat.ibm.audit.authorization_create",   "iam",
             "IBM IAM: Service Authorization Created",
             "A service-to-service authorization was created, granting one IBM service access to another.",
             "iam", "iam.authorization.create"),
        ]
        for rid, svc, title, desc, ibm_svc, op in iam_access:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── audit_activity: COS / Storage ────────────────────────────────
        cos_audit = [
            ("threat.ibm.audit.cos_list_buckets",       "cloud_object_storage",
             "IBM COS: Buckets Listed",
             "Cloud Object Storage buckets were listed. Bucket enumeration reveals data assets.",
             "cloud_object_storage", "cloud-object-storage.bucket.list"),
            ("threat.ibm.audit.cos_get_bucket_policy",  "cloud_object_storage",
             "IBM COS: Bucket IAM Policy Retrieved",
             "The IAM policy for a COS bucket was retrieved. Policy reads reveal access control configuration.",
             "cloud_object_storage", "cloud-object-storage.bucket-acl.get"),
            ("threat.ibm.audit.cos_hmac_key_create",    "cloud_object_storage",
             "IBM COS: HMAC Credentials Created",
             "HMAC credentials were created for IBM COS. HMAC keys enable S3-compatible programmatic access.",
             "cloud_object_storage", "cloud-object-storage.bucket-credentials.create"),
            ("threat.ibm.audit.cos_key_list",           "cloud_object_storage",
             "IBM COS: COS Keys Listed",
             "IBM COS service credentials were listed.",
             "cloud_object_storage", "cloud-object-storage.bucket-credentials.list"),
        ]
        for rid, svc, title, desc, ibm_svc, op in cos_audit:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── audit_activity: KMS / Key Protect ────────────────────────────
        kms_audit = [
            ("threat.ibm.audit.kms_list_keys",          "kms",
             "IBM Key Protect: Keys Listed",
             "Key Protect encryption keys were listed. Key enumeration is a precursor to key extraction.",
             "kms", "kms.secrets.list"),
            ("threat.ibm.audit.kms_wrap_key",           "kms",
             "IBM Key Protect: Key Wrap Operation",
             "A key wrap operation was performed with Key Protect. Wrap/unwrap is used in envelope encryption.",
             "kms", "kms.secrets.wrap"),
            ("threat.ibm.audit.kms_unwrap_key",         "kms",
             "IBM Key Protect: Key Unwrap Operation",
             "A key unwrap (decrypt) operation was performed with Key Protect, decrypting a data encryption key.",
             "kms", "kms.secrets.unwrap"),
            ("threat.ibm.audit.kms_rotate_key",         "kms",
             "IBM Key Protect: Key Rotated",
             "A Key Protect key was rotated. Improper rotation can disrupt encryption-dependent services.",
             "kms", "kms.secrets.rotate"),
            ("threat.ibm.audit.kms_disable_key",        "kms",
             "IBM Key Protect: Encryption Key Disabled",
             "A Key Protect key was disabled. Disabling a key renders encrypted data inaccessible.",
             "kms", "kms.secrets.disable"),
        ]
        for rid, svc, title, desc, ibm_svc, op in kms_audit:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── audit_activity: VPC / IKS ────────────────────────────────────
        vpc_audit = [
            ("threat.ibm.audit.vpc_sg_rule_create",     "is",
             "IBM VPC: Security Group Rule Created",
             "A new security group rule was added in IBM VPC. Rules control network access to compute instances.",
             "is", "is.security-group-rule.create"),
            ("threat.ibm.audit.vpc_sg_rule_delete",     "is",
             "IBM VPC: Security Group Rule Deleted",
             "A security group rule was removed from IBM VPC. Removal may open previously blocked traffic.",
             "is", "is.security-group-rule.delete"),
            ("threat.ibm.audit.iks_get_kubeconfig",     "containers_kubernetes",
             "IBM IKS: Kubernetes Kubeconfig Retrieved",
             "A kubeconfig was retrieved for an IBM Kubernetes Service cluster. Grants direct cluster API access.",
             "containers_kubernetes", "containers.cluster.config.get"),
            ("threat.ibm.audit.iks_list_clusters",      "containers_kubernetes",
             "IBM IKS: Kubernetes Clusters Listed",
             "IBM Kubernetes Service clusters were listed. Enumeration reveals available cluster targets.",
             "containers_kubernetes", "containers.cluster.list"),
        ]
        for rid, svc, title, desc, ibm_svc, op in vpc_audit:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── audit_activity: Activity Tracker / Secrets Manager ───────────
        misc_audit = [
            ("threat.ibm.audit.secrets_get",            "secrets_manager",
             "IBM Secrets Manager: Secret Value Retrieved",
             "A secret value was retrieved from IBM Secrets Manager.",
             "secrets_manager", "secrets-manager.secret.read"),
            ("threat.ibm.audit.secrets_list",           "secrets_manager",
             "IBM Secrets Manager: Secrets Listed",
             "Secrets were listed in IBM Secrets Manager. Enumeration of secret names is reconnaissance.",
             "secrets_manager", "secrets-manager.secret.list"),
            ("threat.ibm.audit.activity_pause",         "logdna",
             "IBM Activity Tracker: Log Collection Paused",
             "IBM Activity Tracker log collection was paused. This creates a gap in the security audit trail.",
             "logdna", "logdna.account.pause_ingestion"),
            ("threat.ibm.audit.event_streams_creds",    "messagehub",
             "IBM Event Streams: Service Credentials Listed",
             "IBM Event Streams (Kafka) service credentials were listed, exposing broker connection details.",
             "messagehub", "messagehub.cluster.read"),
        ]
        for rid, svc, title, desc, ibm_svc, op in misc_audit:
            emit(f, rid, svc, "ibm", title, desc, "audit_activity", "ibm_activity",
                 ibm_act(service=ibm_svc, exact_op=op))
            n += 1

        # ── Network: more IBM VPC port patterns ──────────────────────────
        more_net = [
            ("threat.ibm.network.vpc_telnet_accept",  "vpc_flow", "ibm",
             "IBM VPC: Telnet Traffic Allowed (Port 23)",
             "Telnet (port 23) was allowed. Plaintext protocol exposing credentials.",
             "network", "ibm_vpc_flow", ibm_vpc(dst_port=23, flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_winrm_accept",   "vpc_flow", "ibm",
             "IBM VPC: WinRM Traffic Allowed (Ports 5985/5986)",
             "WinRM allowed through IBM VPC. Enables remote PowerShell execution.",
             "execute", "ibm_vpc_flow", ibm_vpc(dst_ports=[5985, 5986], flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_redis_accept",   "vpc_flow", "ibm",
             "IBM VPC: Redis Port Exposed (Port 6379)",
             "Redis (port 6379) was allowed. Unauthenticated Redis instances are frequently compromised.",
             "network", "ibm_vpc_flow", ibm_vpc(dst_port=6379, flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_smtp_accept",    "vpc_flow", "ibm",
             "IBM VPC: SMTP Traffic Allowed (Port 25)",
             "SMTP (port 25) allowed. Open relay enables spam and data exfiltration.",
             "network", "ibm_vpc_flow", ibm_vpc(dst_port=25, flow_action="ACCEPT")),
            ("threat.ibm.network.vpc_rdp_reject",     "vpc_flow", "ibm",
             "IBM VPC: RDP Traffic Blocked — Possible Brute Force",
             "RDP (port 3389) was rejected, indicating brute-force or scanning activity.",
             "brute_force", "ibm_vpc_flow", ibm_vpc(dst_port=3389, flow_action="REJECT")),
        ]
        for args in more_net:
            emit(f, *args)
            n += 1

        # ── Authorization failures ───────────────────────────────────────
        authz = [
            ("threat.ibm.authorization.kms_denied",    "kms", "ibm",
             "IBM Key Protect: Unauthorized Key Operation",
             "An unauthorized Key Protect operation was denied. May indicate key extraction attempt.",
             "authorization", "ibm_activity", ibm_act(service="kms", outcome="failure")),
            ("threat.ibm.authorization.cos_denied",    "cloud_object_storage", "ibm",
             "IBM COS: Unauthorized Access",
             "An unauthorized COS operation was denied. Repeated denials indicate data access probing.",
             "authorization", "ibm_activity", ibm_act(service="cloud_object_storage", outcome="failure")),
            ("threat.ibm.authorization.secrets_denied","secrets_manager", "ibm",
             "IBM Secrets Manager: Unauthorized Secret Access",
             "An unauthorized Secrets Manager operation was denied.",
             "authorization", "ibm_activity", ibm_act(service="secrets_manager", outcome="failure")),
        ]
        for args in authz:
            emit(f, *args)
            n += 1

        # ── Execute additional ───────────────────────────────────────────
        more_exec = [
            ("threat.ibm.execute.code_engine_run",   "codeengine", "ibm",
             "IBM Code Engine: Job Run Created",
             "An IBM Code Engine job run was created. Code Engine executes arbitrary container workloads.",
             "execute", "ibm_activity", ibm_act(service="codeengine", exact_op="codeengine.job-run.create")),
            ("threat.ibm.execute.vpc_instance_start","is", "ibm",
             "IBM VPC: Instance Started",
             "An IBM VPC virtual server instance was started.",
             "execute", "ibm_activity", ibm_act(service="is", exact_op="is.instance.start")),
        ]
        for args in more_exec:
            emit(f, *args)
            n += 1

        f.write("COMMIT;\n")
    print(f"IBM expanded: {n} → {path}")
    return n


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    total = 0
    total += generate_azure_expanded(out_dir)
    total += generate_gcp_expanded(out_dir)
    total += generate_oci_expanded(out_dir)
    total += generate_ibm_expanded(out_dir)
    print(f"\nTotal new threat rules: {total}")
