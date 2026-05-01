#!/usr/bin/env python3
"""
generate_gcp_ciem_yamls.py

Generates fully-enriched GCP CIEM log-detection rule YAMLs under:
  catalog/rule/gcp_rule_ciem/<service>/gcp.<service>.<log_type>.<operation>.yaml

Usage:
    python3 generate_gcp_ciem_yamls.py
    python3 generate_gcp_ciem_yamls.py --dry-run
"""

import argparse
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
OUT  = ROOT / "catalog" / "rule" / "gcp_rule_ciem"

# ─────────────────────────────────────────────────────────────────────────────
# Lookup tables
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN_BY_CAT = {
    "privilege_escalation":       "identity_and_access_management",
    "persistence":                "identity_and_access_management",
    "credential_access":          "identity_and_access_management",
    "lateral_movement":           "identity_and_access_management",
    "identity_manipulation":      "identity_and_access_management",
    "defense_evasion":            "logging_monitoring_and_alerting",
    "data_exfiltration":          "data_protection_and_privacy",
    "impact":                     "data_protection_and_privacy",
    "execution":                  "compute_and_workload_security",
    "collection":                 "data_protection_and_privacy",
    "supply_chain_compromise":    "configuration_and_change_management",
    "network_attack":             "network_security_and_connectivity",
}

ACTION_BY_CAT = {
    "privilege_escalation":   "privilege_escalation",
    "persistence":            "create",
    "credential_access":      "read",
    "lateral_movement":       "modify",
    "identity_manipulation":  "modify",
    "defense_evasion":        "delete",
    "data_exfiltration":      "read",
    "impact":                 "delete",
    "execution":              "create",
    "collection":             "read",
    "supply_chain_compromise":"create",
    "network_attack":         "modify",
}

POSTURE_BY_CAT = {
    "privilege_escalation":   "iam_posture",
    "persistence":            "iam_posture",
    "credential_access":      "iam_posture",
    "lateral_movement":       "iam_posture",
    "identity_manipulation":  "iam_posture",
    "defense_evasion":        "security_posture",
    "data_exfiltration":      "threat_posture",
    "impact":                 "threat_posture",
    "execution":              "threat_posture",
    "collection":             "threat_posture",
    "supply_chain_compromise":"security_posture",
    "network_attack":         "threat_posture",
}

IAM_CATS = {"privilege_escalation", "persistence", "credential_access",
            "lateral_movement", "identity_manipulation"}

DATA_CATS = {"data_exfiltration", "collection", "impact"}

# compliance_frameworks per threat_category
COMPLIANCE = {
    "privilege_escalation": {
        "cis_gcp_v2":      ["1.1", "1.4", "1.7", "2.4"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "AC-6", "IA-2"],
        "pci_dss_v4":      ["7.1", "7.2", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2", "A.8.3"],
    },
    "persistence": {
        "cis_gcp_v2":      ["1.1", "1.4", "1.12"],
        "nist_800_53_r5":  ["AC-2", "AC-6", "IA-4"],
        "pci_dss_v4":      ["7.1", "8.2", "8.3"],
        "iso_27001_2022":  ["A.5.18", "A.8.2"],
    },
    "credential_access": {
        "cis_gcp_v2":      ["1.6", "1.7", "1.9"],
        "nist_800_53_r5":  ["IA-5", "IA-8", "SC-28"],
        "pci_dss_v4":      ["8.3", "8.6", "10.2"],
        "iso_27001_2022":  ["A.8.5", "A.8.6", "A.5.17"],
    },
    "lateral_movement": {
        "cis_gcp_v2":      ["1.4", "1.7", "3.1"],
        "nist_800_53_r5":  ["AC-4", "SC-7", "SI-4"],
        "pci_dss_v4":      ["7.2", "1.3", "1.4"],
        "iso_27001_2022":  ["A.8.20", "A.8.22", "A.5.18"],
    },
    "identity_manipulation": {
        "cis_gcp_v2":      ["1.1", "1.4", "2.4"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "IA-4"],
        "pci_dss_v4":      ["7.1", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2"],
    },
    "defense_evasion": {
        "cis_gcp_v2":      ["2.1", "2.2", "2.4", "2.5"],
        "nist_800_53_r5":  ["AU-2", "AU-6", "AU-12", "SI-4"],
        "pci_dss_v4":      ["10.1", "10.2", "10.3"],
        "iso_27001_2022":  ["A.8.15", "A.8.16", "A.5.28"],
    },
    "data_exfiltration": {
        "cis_gcp_v2":      ["5.1", "5.2", "7.1"],
        "nist_800_53_r5":  ["AC-4", "DM-2", "SI-4"],
        "pci_dss_v4":      ["3.1", "4.1", "7.1"],
        "iso_27001_2022":  ["A.8.12", "A.5.12", "A.8.10"],
    },
    "impact": {
        "cis_gcp_v2":      ["2.1", "5.1", "6.5"],
        "nist_800_53_r5":  ["CP-9", "CP-10", "SI-7"],
        "pci_dss_v4":      ["12.3", "10.2"],
        "iso_27001_2022":  ["A.8.13", "A.8.14", "A.5.30"],
    },
    "execution": {
        "cis_gcp_v2":      ["4.1", "4.2", "4.3"],
        "nist_800_53_r5":  ["CM-7", "SI-3", "SI-4"],
        "pci_dss_v4":      ["6.3", "6.4"],
        "iso_27001_2022":  ["A.8.19", "A.8.20"],
    },
    "collection": {
        "cis_gcp_v2":      ["5.1", "5.2"],
        "nist_800_53_r5":  ["AC-4", "SC-28", "SI-4"],
        "pci_dss_v4":      ["3.1", "7.1"],
        "iso_27001_2022":  ["A.8.12", "A.5.12"],
    },
    "supply_chain_compromise": {
        "cis_gcp_v2":      ["4.1", "4.2"],
        "nist_800_53_r5":  ["SA-12", "SI-3", "CM-7"],
        "pci_dss_v4":      ["6.3", "12.8"],
        "iso_27001_2022":  ["A.5.19", "A.5.20", "A.8.30"],
    },
    "network_attack": {
        "cis_gcp_v2":      ["3.6", "3.7", "3.8"],
        "nist_800_53_r5":  ["SC-7", "SI-4", "AC-4"],
        "pci_dss_v4":      ["1.3", "1.4"],
        "iso_27001_2022":  ["A.8.20", "A.8.22"],
    },
}

RATIONALE = {
    "T1098.003": (
        "Adversaries add additional roles or permissions to adversary-controlled cloud accounts "
        "to maintain persistent access to a tenant. In GCP, SetIamPolicy on projects, folders, or "
        "organizations enables granting Owner or Editor roles — providing full resource control "
        "without deploying remote access tools. Detected via GCP Admin Activity audit logs."
    ),
    "T1098.006": (
        "Adversaries add roles or permissions to Kubernetes service accounts or workload identities "
        "to maintain persistent cluster access. Creating GKE ClusterRoleBindings or RoleBindings "
        "for attacker-controlled identities enables cluster-wide command execution. "
        "Detected via GKE audit logs for high-privilege role assignments outside CI/CD pipelines."
    ),
    "T1136.003": (
        "Adversaries create cloud accounts — IAM service accounts, Workload Identity Pools, or "
        "new GCP projects — to maintain persistent access without using the initially compromised "
        "identity. New service account keys provide durable authentication that survives credential "
        "rotation of the original account. Detected via IAM Admin Activity audit logs."
    ),
    "T1548": (
        "Adversaries circumvent GCP privilege controls by modifying custom IAM roles to include "
        "broad permissions, using service account impersonation (GenerateAccessToken), or "
        "chaining role assumptions across projects. Detected via iamcredentials.googleapis.com "
        "token generation events and IAM role modification audit logs."
    ),
    "T1552.001": (
        "Adversaries access GCP Secret Manager to retrieve stored credentials, API keys, "
        "and service account key files. Secret Manager access is logged via Data Access audit logs. "
        "Bulk or cross-project secret access by unexpected principals indicates credential harvesting. "
        "Detected via secretmanager.googleapis.com AccessSecretVersion events."
    ),
    "T1562.008": (
        "Adversaries disable or modify GCP Cloud Logging capabilities — deleting log sinks, "
        "updating sinks to filter out admin activity, or deleting log buckets — to prevent "
        "defenders from detecting subsequent malicious actions. Detected via logging.googleapis.com "
        "DeleteSink, UpdateSink, and DeleteBucket events in Admin Activity logs."
    ),
    "T1562.001": (
        "Adversaries modify or disable GCP security controls — muting Security Command Center "
        "findings, deleting notification configurations, disabling Org Policy constraints, or "
        "modifying VPC Service Perimeters — to prevent detection of malicious activity. "
        "Detected via securitycenter.googleapis.com and orgpolicy.googleapis.com audit events."
    ),
    "T1578.002": (
        "Adversaries create new GCP Compute Engine instances to execute malicious workloads, "
        "host C2 infrastructure, or perform cryptomining from within a trusted cloud account. "
        "New VM creation by non-standard principals or from unusual geographic locations "
        "indicates adversary use. Detected via compute.googleapis.com instances.insert."
    ),
    "T1578.001": (
        "Adversaries create persistent disk snapshots in GCP to stage data for exfiltration "
        "or clone production workloads into attacker-controlled projects. Snapshots can be "
        "shared across GCP projects to bypass access controls on the original disk. "
        "Detected via compute.googleapis.com snapshots.insert and setIamPolicy events."
    ),
    "T1530": (
        "Adversaries access data from GCS buckets which may be misconfigured with overly "
        "permissive IAM policies exposing PII, credentials, or proprietary data. "
        "Bulk object reads from new IAM identities or public ACL grants preceding high-volume "
        "downloads indicate active data exfiltration. Detected via storage.googleapis.com "
        "Data Access and Admin Activity audit logs."
    ),
    "T1485": (
        "Adversaries destroy GCP resources — deleting storage buckets, BigQuery datasets, "
        "KMS key versions, or entire GCP projects — to render services inoperable or destroy "
        "evidence. GCP resource deletion is often irreversible without Point-In-Time Recovery. "
        "Detected via Admin Activity audit logs for delete operations on critical resources."
    ),
    "T1609": (
        "Adversaries execute commands within GKE containers via the Kubernetes API exec endpoint, "
        "achieving remote code execution without SSH or network access to the pod. "
        "Pod exec by non-CI/CD service accounts, especially in production namespaces, "
        "indicates unauthorized access. Detected via GKE K8s audit logs for pods/exec."
    ),
    "T1611": (
        "Adversaries escape GKE container isolation by launching privileged pods, mounting "
        "hostPath volumes to sensitive node paths, or exploiting kernel vulnerabilities to "
        "gain host access. Privileged container launches or hostPath mounts from non-standard "
        "principals indicate container escape attempts. Detected via GKE audit logs."
    ),
    "T1610": (
        "Adversaries deploy containers into GKE using the Kubernetes API outside normal "
        "deployment pipelines to host malicious workloads. Images not in an approved registry, "
        "privileged mode, or host namespace access indicate adversary container deployment. "
        "Detected via GKE K8s audit logs for pod creation by non-CI/CD principals."
    ),
    "T1651": (
        "Adversaries abuse GCP Compute Engine's setMetadata API to inject startup scripts into "
        "running instances — achieving remote code execution through the cloud control plane "
        "without SSH access. Script injection via project-wide or instance metadata changes "
        "is detected via compute.googleapis.com setMetadata Admin Activity events."
    ),
    "T1572": (
        "Adversaries create VPN tunnels or Cloud Interconnect attachments in GCP to establish "
        "encrypted communication channels that bypass network monitoring. New VPN tunnel creation "
        "by non-networking team principals indicates adversary-controlled C2 infrastructure. "
        "Detected via compute.googleapis.com vpnTunnels.insert audit events."
    ),
    "T1583.002": (
        "Adversaries create Cloud DNS managed zones or modify DNS records to establish "
        "attacker-controlled infrastructure or redirect legitimate traffic. DNS zone creation "
        "combined with record modification is a precursor to domain fronting or DNS hijacking. "
        "Detected via dns.googleapis.com Admin Activity logs."
    ),
    "T1565.002": (
        "Adversaries patch Cloud DNS resource record sets to redirect legitimate DNS queries "
        "to attacker-controlled endpoints. Modifying authoritative DNS records for critical "
        "domains enables traffic interception, credential harvesting, or MitM attacks. "
        "Detected via dns.googleapis.com resourceRecordSets.patch events."
    ),
    "T1648": (
        "Adversaries deploy or modify GCP Cloud Functions or Cloud Run services to establish "
        "serverless compute resources for malicious purposes — C2 callbacks, data exfiltration, "
        "or persistence. Function deployment by unexpected principals or with unusual environment "
        "variables containing credentials. Detected via cloudfunctions.googleapis.com events."
    ),
    "T1599": (
        "Adversaries create custom network routes in GCP VPC to redirect traffic through "
        "adversary-controlled instances, enabling man-in-the-middle attacks on internal network "
        "traffic. Route injection by non-network engineering identities is a strong indicator "
        "of compromise. Detected via compute.googleapis.com routes.insert."
    ),
}

REMEDIATION = {
    "privilege_escalation": """\
1. Immediately audit the modified IAM policy and revoke unauthorized role grants.
2. Enable Cloud Asset Inventory change notifications for IAM policy updates.
3. Apply Org Policy constraints to restrict role assignment to approved principals.
4. Require two-person approval for Owner/Editor role grants via Cloud Identity workflows.
5. Configure VPC Service Controls to prevent cross-project privilege escalation.
""",
    "persistence": """\
1. Audit and disable the newly created service account or Workload Identity Pool.
2. Review all service account keys and revoke unexpected user-managed keys.
3. Apply Org Policy `iam.disableServiceAccountCreation` for non-admin projects.
4. Enable Security Command Center alerts for new service account creation events.
5. Rotate credentials for any accounts that interacted with the new identity.
""",
    "credential_access": """\
1. Immediately rotate or disable the accessed credential / secret.
2. Review all Access Context Manager policies for unexpected secret access.
3. Enable Secret Manager audit logs (Data Access) and alert on AccessSecretVersion.
4. Apply CMEK to Secret Manager and restrict IAM to least-privilege consumers.
5. Use Workload Identity Federation instead of long-lived service account keys.
""",
    "lateral_movement": """\
1. Revoke the service account impersonation grant (roles/iam.serviceAccountTokenCreator).
2. Audit all GenerateAccessToken calls in iamcredentials.googleapis.com audit logs.
3. Restrict service account impersonation using IAM Conditions (resource-based restrictions).
4. Enable Security Command Center lateral movement threat findings.
5. Rotate credentials for all service accounts involved in the impersonation chain.
""",
    "identity_manipulation": """\
1. Revoke the unauthorized IAM change and restore the previous policy version.
2. Enable policy change notifications via Cloud Asset Feeds and Pub/Sub alerts.
3. Use Cloud Identity's admin privilege just-in-time (JIT) access workflow.
4. Enable organization-wide audit logs for all IAM write operations.
5. Require MFA for all administrative actions via Identity-Aware Proxy.
""",
    "defense_evasion": """\
1. Immediately restore the deleted or modified logging/security configuration.
2. Apply Org Policy to prevent log sink deletion: `logging.restrictSinkCreation`.
3. Use Cloud Storage Bucket Lock on log export buckets to prevent deletion.
4. Configure out-of-band alerting via Pub/Sub → Cloud Functions for audit log changes.
5. Enable Security Command Center Premium for threat detection on defense evasion events.
""",
    "data_exfiltration": """\
1. Audit and revoke the IAM binding granting public or broad access to the resource.
2. Enable VPC Service Controls to restrict data exfiltration to approved perimeters.
3. Configure DLP inspection on Cloud Storage and BigQuery for sensitive data.
4. Set up Cloud Monitoring alerts on bulk data read operations by unexpected principals.
5. Enable CMEK for storage and BigQuery to prevent data use without key access.
""",
    "impact": """\
1. Restore the deleted resource from Cloud Storage versioning, BigQuery snapshots, or Persistent Disk snapshot.
2. Enable Cloud Storage Object Versioning and Bucket Lock for critical buckets.
3. Apply Org Policy `constraints/gcp.resourceLocations` to restrict deletion regions.
4. Set up Cloud Asset Inventory change notifications for resource deletion events.
5. Require two-person approval for project deletion via Resource Manager policy.
""",
    "execution": """\
1. Audit the compute instance or function for malicious startup scripts or code.
2. Verify the workload image against a trusted artifact registry with Binary Authorization.
3. Apply Org Policy `compute.requireShieldedVm` for all new VM instances.
4. Enable Security Command Center threats for anomalous compute execution events.
5. Review service account permissions attached to the created instance or function.
""",
    "collection": """\
1. Audit and revert the snapshot or data access operation.
2. Review IAM permissions on the affected disk/volume and revoke unauthorized access.
3. Enable disk snapshot sharing restrictions via Org Policy.
4. Configure Security Command Center alerts for snapshot cross-project share events.
5. Encrypt all persistent disks with CMEK to prevent use without key access.
""",
    "supply_chain_compromise": """\
1. Audit the deployed function or container image for malicious dependencies.
2. Enable Binary Authorization to require signed images from trusted registries.
3. Restrict function/service deployment IAM roles to CI/CD service accounts only.
4. Scan all deployed packages using Artifact Registry vulnerability scanning.
5. Configure Org Policy to restrict allowed container registries for Cloud Run.
""",
    "network_attack": """\
1. Audit and delete the unauthorized VPN tunnel, route, or firewall rule.
2. Review VPC network topology for unexpected routes or peering connections.
3. Enable VPC Flow Logs on all subnets and alert on anomalous traffic patterns.
4. Apply Org Policy firewall constraints to restrict inbound SSH/RDP from 0.0.0.0/0.
5. Use Cloud Armor security policies to protect public-facing workloads.
""",
}

REFERENCES = {
    "T1098.003": [
        "https://attack.mitre.org/techniques/T1098/003/",
        "https://cloud.google.com/iam/docs/audit-logging",
        "https://cloud.google.com/resource-manager/docs/audit-logging",
    ],
    "T1098.006": [
        "https://attack.mitre.org/techniques/T1098/006/",
        "https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging",
    ],
    "T1136.003": [
        "https://attack.mitre.org/techniques/T1136/003/",
        "https://cloud.google.com/iam/docs/audit-logging",
    ],
    "T1548": [
        "https://attack.mitre.org/techniques/T1548/",
        "https://cloud.google.com/iam/docs/impersonating-service-accounts",
    ],
    "T1552.001": [
        "https://attack.mitre.org/techniques/T1552/001/",
        "https://cloud.google.com/secret-manager/docs/audit-logging",
    ],
    "T1562.008": [
        "https://attack.mitre.org/techniques/T1562/008/",
        "https://cloud.google.com/logging/docs/audit",
        "https://cloud.google.com/logging/docs/export/configure_export_v2",
    ],
    "T1562.001": [
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://cloud.google.com/security-command-center/docs/concepts-security-sources",
    ],
    "T1578.002": [
        "https://attack.mitre.org/techniques/T1578/002/",
        "https://cloud.google.com/compute/docs/audit-logging",
    ],
    "T1578.001": [
        "https://attack.mitre.org/techniques/T1578/001/",
        "https://cloud.google.com/compute/docs/disks/snapshots",
    ],
    "T1530": [
        "https://attack.mitre.org/techniques/T1530/",
        "https://cloud.google.com/storage/docs/audit-logging",
        "https://cloud.google.com/bigquery/docs/audit-logging",
    ],
    "T1485": [
        "https://attack.mitre.org/techniques/T1485/",
        "https://cloud.google.com/storage/docs/object-versioning",
        "https://cloud.google.com/kms/docs/audit-logging",
    ],
    "T1609": [
        "https://attack.mitre.org/techniques/T1609/",
        "https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging",
    ],
    "T1611": [
        "https://attack.mitre.org/techniques/T1611/",
        "https://cloud.google.com/kubernetes-engine/docs/how-to/pod-security-admission",
    ],
    "T1610": [
        "https://attack.mitre.org/techniques/T1610/",
        "https://cloud.google.com/binary-authorization/docs/overview",
    ],
    "T1651": [
        "https://attack.mitre.org/techniques/T1651/",
        "https://cloud.google.com/compute/docs/metadata/overview",
    ],
    "T1572": [
        "https://attack.mitre.org/techniques/T1572/",
        "https://cloud.google.com/network-connectivity/docs/vpn/concepts/overview",
    ],
    "T1583.002": [
        "https://attack.mitre.org/techniques/T1583/002/",
        "https://cloud.google.com/dns/docs/audit-logging",
    ],
    "T1565.002": [
        "https://attack.mitre.org/techniques/T1565/002/",
        "https://cloud.google.com/dns/docs/audit-logging",
    ],
    "T1648": [
        "https://attack.mitre.org/techniques/T1648/",
        "https://cloud.google.com/functions/docs/concepts/overview",
        "https://cloud.google.com/run/docs/audit-logging",
    ],
    "T1599": [
        "https://attack.mitre.org/techniques/T1599/",
        "https://cloud.google.com/vpc/docs/routes",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions  (compact — enrichment auto-derived from lookup tables)
# ─────────────────────────────────────────────────────────────────────────────

RULES = [
    # ── IAM ──────────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.iam.activity.set_iam_policy",
        "service": "iam", "severity": "high",
        "title": "IAM: Set IAM Policy on Resource",
        "description": "IAM policy modified on a GCP project, folder, or organization — potential privilege escalation or persistence.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.003"],
        "risk_score": 78,
        "resource": "iam_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.owner_role_granted",
        "service": "iam", "severity": "critical",
        "title": "IAM: Owner Role Granted on Project or Organization",
        "description": "roles/owner or roles/editor granted on a GCP project or organization — full administrative access acquired.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.003"],
        "risk_score": 95,
        "resource": "iam_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.create_service_account",
        "service": "iam", "severity": "medium",
        "title": "IAM: Service Account Created",
        "description": "New GCP service account created — potential persistence mechanism for maintaining cloud access.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 60,
        "resource": "service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateServiceAccount"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.create_service_account_key",
        "service": "iam", "severity": "high",
        "title": "IAM: Service Account Key Created",
        "description": "User-managed key created for a GCP service account — long-lived credential that persists outside normal rotation cycles.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 75,
        "resource": "service_account_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateServiceAccountKey"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.delete_service_account_key",
        "service": "iam", "severity": "medium",
        "title": "IAM: Service Account Key Deleted",
        "description": "Service account key deleted — may be covering tracks after credential exfiltration.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 55,
        "resource": "service_account_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteServiceAccountKey"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.create_custom_role",
        "service": "iam", "severity": "medium",
        "title": "IAM: Custom Role Created",
        "description": "Custom IAM role created in GCP project or organization — may contain overly broad permissions bypassing predefined role restrictions.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 65,
        "resource": "iam_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateRole"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.update_custom_role",
        "service": "iam", "severity": "high",
        "title": "IAM: Custom Role Updated with Broad Permissions",
        "description": "Existing custom IAM role modified — permissions may have been expanded to enable privilege escalation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 72,
        "resource": "iam_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateRole"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.disable_service_account",
        "service": "iam", "severity": "medium",
        "title": "IAM: Service Account Disabled",
        "description": "Service account disabled — may disrupt legitimate workloads or cover unauthorized access from that identity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 50,
        "resource": "service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DisableServiceAccount"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.activity.workload_identity_pool_created",
        "service": "iam", "severity": "medium",
        "title": "IAM: Workload Identity Pool Created",
        "description": "New Workload Identity Pool or Provider created — establishes external identity federation that may grant cloud access to attacker-controlled identity providers.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "privilege_escalation"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 68,
        "resource": "workload_identity_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateWorkloadIdentityPool"},
        ]}},
    },
    # ── IAM Credentials (impersonation) ──────────────────────────────────────
    {
        "rule_id": "gcp.iam.credentials.generate_access_token",
        "service": "iam", "severity": "high",
        "title": "IAM Credentials: Service Account Access Token Generated",
        "description": "Access token generated for another service account via GenerateAccessToken — service account impersonation for lateral movement.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement", "privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 78,
        "resource": "service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "GenerateAccessToken"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.credentials.sign_blob",
        "service": "iam", "severity": "medium",
        "title": "IAM Credentials: Service Account Blob Signing",
        "description": "Arbitrary data blob signed using a service account key — may be used to forge authentication tokens for other GCP services.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 62,
        "resource": "service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SignBlob"},
        ]}},
    },
    # ── Cloud Logging ─────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.logging.activity.delete_sink",
        "service": "logging", "severity": "critical",
        "title": "Logging: Log Export Sink Deleted",
        "description": "Cloud Logging export sink deleted — audit log stream interrupted, preventing log export to SIEM or Cloud Storage.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 92,
        "resource": "log_sink",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteSink"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.activity.update_sink",
        "service": "logging", "severity": "high",
        "title": "Logging: Log Export Sink Updated",
        "description": "Log export sink configuration changed — filter may have been modified to exclude admin activity or data access logs.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 80,
        "resource": "log_sink",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateSink"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.activity.delete_log_bucket",
        "service": "logging", "severity": "high",
        "title": "Logging: Log Bucket Deleted",
        "description": "Cloud Logging bucket deleted — stored audit logs destroyed, eliminating forensic evidence of preceding activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 88,
        "resource": "log_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteBucket"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.activity.update_log_bucket",
        "service": "logging", "severity": "high",
        "title": "Logging: Log Bucket Retention Modified",
        "description": "Cloud Logging bucket updated — retention period may have been shortened or bucket lock disabled to facilitate log deletion.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 75,
        "resource": "log_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateBucket"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.activity.delete_exclusion",
        "service": "logging", "severity": "medium",
        "title": "Logging: Log Exclusion Deleted",
        "description": "Log exclusion filter deleted — change to what events are captured; may indicate attempt to remove a filter that was hiding attacker activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 55,
        "resource": "log_exclusion",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteExclusion"},
        ]}},
    },
    # ── Security Command Center ───────────────────────────────────────────────
    {
        "rule_id": "gcp.scc.activity.bulk_mute_findings",
        "service": "scc", "severity": "high",
        "title": "SCC: Security Findings Bulk Muted",
        "description": "Security Command Center findings muted in bulk — security alerts suppressed to prevent analyst investigation of ongoing attack.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 85,
        "resource": "scc_finding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "BulkMuteFindings"},
        ]}},
    },
    {
        "rule_id": "gcp.scc.activity.delete_notification_config",
        "service": "scc", "severity": "high",
        "title": "SCC: Notification Configuration Deleted",
        "description": "Security Command Center notification config deleted — real-time security alerts to Pub/Sub or SIEM disabled.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 82,
        "resource": "scc_notification",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteNotificationConfig"},
        ]}},
    },
    {
        "rule_id": "gcp.scc.activity.update_source",
        "service": "scc", "severity": "medium",
        "title": "SCC: Security Source Updated",
        "description": "Security Command Center source configuration modified — threat detection rules or source integrations altered.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 60,
        "resource": "scc_source",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateSource"},
        ]}},
    },
    # ── Compute Engine ────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.compute.activity.instance_insert",
        "service": "compute", "severity": "medium",
        "title": "Compute: VM Instance Created",
        "description": "New GCP Compute Engine instance created — potential cryptomining, C2 hosting, or pivot point in attacker-controlled environment.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1578.002"],
        "risk_score": 55,
        "resource": "compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "instances.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.set_metadata",
        "service": "compute", "severity": "high",
        "title": "Compute: Instance Metadata Modified (Startup Script Injection)",
        "description": "Instance metadata modified via setMetadata — adversaries inject startup scripts to achieve persistent code execution on VMs without SSH access.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1651"],
        "risk_score": 82,
        "resource": "compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "setMetadata"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.project_set_metadata",
        "service": "compute", "severity": "critical",
        "title": "Compute: Project-Wide Instance Metadata Modified",
        "description": "Project-wide instance metadata modified via setCommonInstanceMetadata — startup script injection affecting ALL VMs in the project simultaneously.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "lateral_movement"],
        "mitre_techniques": ["T1651"],
        "risk_score": 90,
        "resource": "gcp_project",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "setCommonInstanceMetadata"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.firewall_insert",
        "service": "compute", "severity": "medium",
        "title": "Compute: Firewall Rule Created",
        "description": "New VPC firewall rule created — may allow inbound access from attacker-controlled IPs or open sensitive ports to the internet.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 62,
        "resource": "vpc_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "firewalls.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.firewall_delete",
        "service": "compute", "severity": "medium",
        "title": "Compute: Firewall Rule Deleted",
        "description": "VPC firewall rule deleted — security boundary removed, potentially exposing instances to unintended network access.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 65,
        "resource": "vpc_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "firewalls.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.snapshot_insert",
        "service": "compute", "severity": "high",
        "title": "Compute: Persistent Disk Snapshot Created",
        "description": "Disk snapshot created — may be cross-project shared to exfiltrate disk contents containing sensitive data, credentials, or application secrets.",
        "threat_category": "collection",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1578.001"],
        "risk_score": 72,
        "resource": "compute_snapshot",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "snapshots.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.route_insert",
        "service": "compute", "severity": "medium",
        "title": "Compute: Custom Network Route Created",
        "description": "Custom VPC route created — adversaries inject routes to redirect traffic through attacker-controlled instances for interception.",
        "threat_category": "network_attack",
        "mitre_tactics": ["lateral_movement", "collection"],
        "mitre_techniques": ["T1599"],
        "risk_score": 68,
        "resource": "vpc_route",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "routes.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.activity.vpn_tunnel_insert",
        "service": "compute", "severity": "medium",
        "title": "Compute: VPN Tunnel Created",
        "description": "VPN tunnel created in GCP VPC — may establish encrypted C2 channel bypassing perimeter monitoring.",
        "threat_category": "network_attack",
        "mitre_tactics": ["command_and_control"],
        "mitre_techniques": ["T1572"],
        "risk_score": 62,
        "resource": "vpn_tunnel",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "vpnTunnels.insert"},
        ]}},
    },
    # ── Cloud Storage ─────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.storage.activity.bucket_delete",
        "service": "storage", "severity": "high",
        "title": "Storage: GCS Bucket Deleted",
        "description": "Cloud Storage bucket deleted — data destruction or evidence removal; may be irreversible without versioning enabled.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 82,
        "resource": "gcs_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "storage.buckets.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.activity.set_iam_policy",
        "service": "storage", "severity": "critical",
        "title": "Storage: GCS Bucket IAM Policy Modified (Public Access)",
        "description": "IAM policy modified on a GCS bucket — may grant allUsers or allAuthenticatedUsers access, exposing data to the public internet.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 90,
        "resource": "gcs_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "storage.setIamPermissions"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.data_access.objects_bulk_read",
        "service": "storage", "severity": "high",
        "title": "Storage: Bulk GCS Object Read",
        "description": "High volume of GCS object reads by a single principal — indicative of data staging for exfiltration.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 78,
        "resource": "gcs_object",
        "log_source_type": "gcp_data_access",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "storage.objects.get"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.activity.bucket_update_acl",
        "service": "storage", "severity": "high",
        "title": "Storage: GCS Bucket ACL Updated",
        "description": "GCS bucket ACL modified — legacy ACL change may grant public read/write access bypassing uniform bucket-level access controls.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 75,
        "resource": "gcs_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "storage.buckets.update"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.activity.objects_bulk_delete",
        "service": "storage", "severity": "high",
        "title": "Storage: Bulk GCS Object Deletion",
        "description": "Multiple GCS objects deleted in short succession — large-scale data destruction or evidence removal.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "gcs_object",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "storage.objects.delete"},
        ]}},
    },
    # ── BigQuery ──────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.bigquery.activity.dataset_delete",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Dataset Deleted",
        "description": "BigQuery dataset deleted — potential data destruction impacting analytics and data warehouse workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 80,
        "resource": "bigquery_dataset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "datasetservice.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.activity.job_insert_extract",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Data Export Job Created",
        "description": "BigQuery extract job submitted — data exported to GCS or external destination; may indicate large-scale data exfiltration.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 78,
        "resource": "bigquery_job",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "jobservice.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.activity.dataset_set_iam_policy",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Dataset IAM Policy Modified",
        "description": "BigQuery dataset access policy changed — may grant allUsers or unexpected principals read access to sensitive data tables.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration", "privilege_escalation"],
        "mitre_techniques": ["T1530"],
        "risk_score": 75,
        "resource": "bigquery_dataset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "datasetservice.update"},
        ]}},
    },
    # ── GKE / Container ───────────────────────────────────────────────────────
    {
        "rule_id": "gcp.container.activity.cluster_create",
        "service": "container", "severity": "medium",
        "title": "GKE: Cluster Created",
        "description": "New GKE cluster created — may be provisioned with insecure defaults (legacy auth, public endpoint, no network policy) for adversary use.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1610"],
        "risk_score": 58,
        "resource": "gke_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateCluster"},
        ]}},
    },
    {
        "rule_id": "gcp.container.activity.cluster_delete",
        "service": "container", "severity": "high",
        "title": "GKE: Cluster Deleted",
        "description": "GKE cluster deleted — workload disruption or evidence destruction of containerized attacker activity.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 80,
        "resource": "gke_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteCluster"},
        ]}},
    },
    {
        "rule_id": "gcp.container.activity.cluster_update_legacy_abac",
        "service": "container", "severity": "high",
        "title": "GKE: Legacy ABAC Enabled on Cluster",
        "description": "Legacy Attribute-Based Access Control (ABAC) enabled on GKE cluster — bypasses modern RBAC controls, granting broad permissions to all authenticated users.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "privilege_escalation"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 82,
        "resource": "gke_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SetLegacyAbac"},
        ]}},
    },
    {
        "rule_id": "gcp.container.k8s.pod_exec",
        "service": "container", "severity": "high",
        "title": "GKE K8s: Pod Exec Command Executed",
        "description": "kubectl exec used to execute commands inside a running pod — interactive shell access to a container workload by an unexpected principal.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 80,
        "resource": "k8s_pod",
        "log_source_type": "k8s_audit",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "equals", "value": "exec"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "gcp.container.k8s.privileged_pod_create",
        "service": "container", "severity": "critical",
        "title": "GKE K8s: Privileged Pod Created",
        "description": "Pod created with privileged security context — container escape risk, allowing access to the underlying GKE node and its credentials.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "execution"],
        "mitre_techniques": ["T1611"],
        "risk_score": 92,
        "resource": "k8s_pod",
        "log_source_type": "k8s_audit",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "gcp.container.k8s.cluster_role_binding_create",
        "service": "container", "severity": "high",
        "title": "GKE K8s: ClusterRoleBinding Created",
        "description": "Kubernetes ClusterRoleBinding created — grants cluster-wide permissions to a subject, potentially providing cluster-admin access to an attacker-controlled identity.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 85,
        "resource": "k8s_cluster_role_binding",
        "log_source_type": "k8s_audit",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "clusterrolebindings"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "gcp.container.k8s.role_binding_create",
        "service": "container", "severity": "medium",
        "title": "GKE K8s: RoleBinding Created",
        "description": "Kubernetes RoleBinding created — grants namespace-scoped permissions to a subject outside normal deployment pipelines.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 65,
        "resource": "k8s_role_binding",
        "log_source_type": "k8s_audit",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "rolebindings"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "gcp.container.k8s.secret_access",
        "service": "container", "severity": "high",
        "title": "GKE K8s: Kubernetes Secret Accessed",
        "description": "Kubernetes Secret read outside normal pod runtime — credentials stored in K8s Secrets accessed directly by an unexpected user or service account.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 78,
        "resource": "k8s_secret",
        "log_source_type": "k8s_audit",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "in", "value": ["get", "list", "watch"]},
        ]}},
    },
    # ── Secret Manager ────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.secretmanager.data_access.access_secret_version",
        "service": "secretmanager", "severity": "high",
        "title": "Secret Manager: Secret Version Accessed",
        "description": "Secret Manager secret version accessed — credentials, API keys, or TLS certificates retrieved; access by unexpected principal indicates credential harvesting.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 78,
        "resource": "secret",
        "log_source_type": "gcp_data_access",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "AccessSecretVersion"},
        ]}},
    },
    {
        "rule_id": "gcp.secretmanager.activity.destroy_secret_version",
        "service": "secretmanager", "severity": "high",
        "title": "Secret Manager: Secret Version Destroyed",
        "description": "Secret version permanently destroyed — credential rotations disrupted or key material deleted to cover attacker tracks.",
        "threat_category": "impact",
        "mitre_tactics": ["impact", "defense_evasion"],
        "mitre_techniques": ["T1485"],
        "risk_score": 80,
        "resource": "secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DestroySecretVersion"},
        ]}},
    },
    {
        "rule_id": "gcp.secretmanager.activity.delete_secret",
        "service": "secretmanager", "severity": "high",
        "title": "Secret Manager: Secret Deleted",
        "description": "Secret deleted from Secret Manager — credential removed, potentially disrupting application authentication or covering tracks.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 75,
        "resource": "secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteSecret"},
        ]}},
    },
    # ── Cloud Functions ───────────────────────────────────────────────────────
    {
        "rule_id": "gcp.cloudfunctions.activity.create_function",
        "service": "cloudfunctions", "severity": "medium",
        "title": "Cloud Functions: Function Created",
        "description": "Cloud Function created — serverless code deployed outside normal CI/CD pipelines may contain malicious logic for data exfiltration or C2 callbacks.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1648"],
        "risk_score": 60,
        "resource": "cloud_function",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudfunctions.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateFunction"},
        ]}},
    },
    {
        "rule_id": "gcp.cloudfunctions.activity.update_function",
        "service": "cloudfunctions", "severity": "high",
        "title": "Cloud Functions: Function Code Updated",
        "description": "Existing Cloud Function code or configuration updated — may inject malicious code into a trusted function used by production workflows.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1648"],
        "risk_score": 72,
        "resource": "cloud_function",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudfunctions.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateFunction"},
        ]}},
    },
    # ── Cloud Resource Manager ────────────────────────────────────────────────
    {
        "rule_id": "gcp.resourcemanager.activity.delete_project",
        "service": "resourcemanager", "severity": "critical",
        "title": "Resource Manager: GCP Project Deleted",
        "description": "GCP project deletion initiated — destroys all resources, audit logs, and data in the project; potential ransomware or cover-tracks operation.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "gcp_project",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteProject"},
        ]}},
    },
    {
        "rule_id": "gcp.resourcemanager.activity.create_project",
        "service": "resourcemanager", "severity": "medium",
        "title": "Resource Manager: New GCP Project Created",
        "description": "New GCP project created — adversaries may create shadow projects outside normal billing and security monitoring to operate covertly.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 60,
        "resource": "gcp_project",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateProject"},
        ]}},
    },
    {
        "rule_id": "gcp.resourcemanager.activity.set_org_iam_policy",
        "service": "resourcemanager", "severity": "critical",
        "title": "Resource Manager: Organization-Level IAM Policy Modified",
        "description": "IAM policy set on the GCP organization — grants roles affecting all projects and folders; adversary with org-level Owner access controls entire tenant.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.003"],
        "risk_score": 96,
        "resource": "gcp_organization",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
        ]}},
    },
    # ── Org Policy ────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.orgpolicy.activity.create_policy",
        "service": "orgpolicy", "severity": "high",
        "title": "Org Policy: Custom Policy Created",
        "description": "Organization policy created — may override security-critical constraints such as public IP restrictions, service account key creation, or resource location policies.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 78,
        "resource": "org_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "orgpolicy.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreatePolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.orgpolicy.activity.update_policy",
        "service": "orgpolicy", "severity": "high",
        "title": "Org Policy: Security Constraint Policy Updated",
        "description": "Organization policy modified — existing security guardrail may have been relaxed or disabled, removing enforcement of critical security constraints.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 82,
        "resource": "org_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "orgpolicy.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdatePolicy"},
        ]}},
    },
    # ── KMS ───────────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.kms.activity.destroy_crypto_key_version",
        "service": "kms", "severity": "critical",
        "title": "KMS: Crypto Key Version Destroyed",
        "description": "KMS crypto key version destruction scheduled or executed — data encrypted with this key becomes permanently unrecoverable; ransomware indicator.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DestroyCryptoKeyVersion"},
        ]}},
    },
    {
        "rule_id": "gcp.kms.activity.disable_crypto_key_version",
        "service": "kms", "severity": "high",
        "title": "KMS: Crypto Key Version Disabled",
        "description": "KMS crypto key version disabled — encrypted resources (disks, secrets, BigQuery) become inaccessible; potential ransomware or service disruption.",
        "threat_category": "impact",
        "mitre_tactics": ["impact", "defense_evasion"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateCryptoKeyVersion"},
        ]}},
    },
    {
        "rule_id": "gcp.kms.activity.set_iam_policy",
        "service": "kms", "severity": "high",
        "title": "KMS: Crypto Key IAM Policy Modified",
        "description": "IAM policy modified on a KMS key — may grant decrypt access to unauthorized principals, enabling access to all resources encrypted with this key.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "credential_access"],
        "mitre_techniques": ["T1098.003"],
        "risk_score": 82,
        "resource": "kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
        ]}},
    },
    # ── Cloud DNS ─────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.dns.activity.managed_zone_create",
        "service": "dns", "severity": "medium",
        "title": "DNS: Managed Zone Created",
        "description": "Cloud DNS managed zone created — attacker may establish adversary-controlled DNS infrastructure to support phishing or domain fronting.",
        "threat_category": "network_attack",
        "mitre_tactics": ["resource_development"],
        "mitre_techniques": ["T1583.002"],
        "risk_score": 55,
        "resource": "dns_zone",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "dns.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "managedZones.create"},
        ]}},
    },
    {
        "rule_id": "gcp.dns.activity.record_set_patch",
        "service": "dns", "severity": "high",
        "title": "DNS: Resource Record Set Modified (DNS Hijacking Risk)",
        "description": "DNS resource record set patched — modification of authoritative records can redirect legitimate traffic to attacker-controlled endpoints for credential harvesting.",
        "threat_category": "network_attack",
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1565.002"],
        "risk_score": 82,
        "resource": "dns_record",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "dns.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "resourceRecordSets"},
        ]}},
    },
    # ── Cloud SQL ─────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.sql.activity.instance_delete",
        "service": "sql", "severity": "high",
        "title": "Cloud SQL: Database Instance Deleted",
        "description": "Cloud SQL instance deleted — loss of managed database service; may be irreversible without automated backup.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "sqladmin.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "instances.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.sql.activity.export_instance",
        "service": "sql", "severity": "high",
        "title": "Cloud SQL: Database Export Executed",
        "description": "Cloud SQL database exported to GCS — full database dump created, which may contain PII, credentials, or sensitive business data.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 80,
        "resource": "sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "sqladmin.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "instances.export"},
        ]}},
    },
    {
        "rule_id": "gcp.sql.activity.user_insert",
        "service": "sql", "severity": "medium",
        "title": "Cloud SQL: New Database User Created",
        "description": "New Cloud SQL user created — unauthorized database account may provide persistent access to database contents.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 62,
        "resource": "sql_user",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "sqladmin.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "users.insert"},
        ]}},
    },
    # ── Cloud Run ─────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.cloudrun.activity.create_service",
        "service": "cloudrun", "severity": "medium",
        "title": "Cloud Run: Service Created",
        "description": "Cloud Run service deployed — serverless container deployment outside normal CI/CD may serve as C2 endpoint or data exfiltration pipeline.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1648"],
        "risk_score": 58,
        "resource": "cloudrun_service",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "run.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateService"},
        ]}},
    },
    {
        "rule_id": "gcp.cloudrun.activity.replace_service",
        "service": "cloudrun", "severity": "high",
        "title": "Cloud Run: Service Updated",
        "description": "Existing Cloud Run service image or configuration replaced — production workload may have been backdoored with malicious container image.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1648"],
        "risk_score": 72,
        "resource": "cloudrun_service",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "run.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "ReplaceService"},
        ]}},
    },
    # ── VPC Service Controls ──────────────────────────────────────────────────
    {
        "rule_id": "gcp.accesscontextmanager.activity.update_service_perimeter",
        "service": "accesscontextmanager", "severity": "high",
        "title": "Access Context Manager: VPC Service Perimeter Updated",
        "description": "VPC Service Controls perimeter updated — data exfiltration prevention boundary may have been expanded or had services removed, allowing data movement out of the secured perimeter.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "exfiltration"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 85,
        "resource": "service_perimeter",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "accesscontextmanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "UpdateServicePerimeter"},
        ]}},
    },
    {
        "rule_id": "gcp.accesscontextmanager.activity.delete_service_perimeter",
        "service": "accesscontextmanager", "severity": "critical",
        "title": "Access Context Manager: VPC Service Perimeter Deleted",
        "description": "VPC Service Controls perimeter deleted — entire data exfiltration prevention boundary removed, leaving GCP APIs and data unprotected from exfiltration.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "exfiltration"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 93,
        "resource": "service_perimeter",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "accesscontextmanager.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteServicePerimeter"},
        ]}},
    },
    # ── Pub/Sub (collection channel) ──────────────────────────────────────────
    {
        "rule_id": "gcp.pubsub.activity.subscription_create",
        "service": "pubsub", "severity": "medium",
        "title": "Pub/Sub: Subscription Created on Sensitive Topic",
        "description": "Pub/Sub subscription created — may establish a collection channel consuming log or event messages from security-critical topics.",
        "threat_category": "collection",
        "mitre_tactics": ["collection"],
        "mitre_techniques": ["T1530"],
        "risk_score": 55,
        "resource": "pubsub_subscription",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "pubsub.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "CreateSubscription"},
        ]}},
    },
    {
        "rule_id": "gcp.pubsub.activity.topic_delete",
        "service": "pubsub", "severity": "medium",
        "title": "Pub/Sub: Topic Deleted",
        "description": "Pub/Sub topic deleted — disrupts event-driven integrations; may disable security alerting pipelines if the topic was used for SIEM forwarding.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "impact"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 60,
        "resource": "pubsub_topic",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "pubsub.googleapis.com"},
            {"field": "operation",   "op": "contains", "value": "DeleteTopic"},
        ]}},
    },
    # ── Correlation chains ─────────────────────────────────────────────────────
    {
        "rule_id": "gcp.ciem.correlation.privilege_escalation_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP: Privilege Escalation Chain — SetIamPolicy + Token Generation",
        "description": "Correlated GCP privilege escalation: IAM policy change granting elevated role followed by service account token generation — indicates role grant used immediately for impersonation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.003", "T1548"],
        "risk_score": 95,
        "resource": "iam_policy",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "GenerateAccessToken"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.correlation.defense_evasion_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP: Defense Evasion Chain — Log Sink + SCC Finding Mute",
        "description": "Correlated defense evasion: Cloud Logging sink deleted or modified followed by SCC findings muted — systematic disabling of both logging and alerting controls.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008", "T1562.001"],
        "risk_score": 95,
        "resource": "log_sink",
        "check_config": {
            "type": "sequence",
            "window_seconds": 600,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
                    {"field": "operation",   "op": "in", "value": ["DeleteSink", "UpdateSink"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "MuteFindings"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.correlation.data_exfiltration_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP: Data Exfiltration Chain — Public ACL Grant + Bulk Read",
        "description": "Correlated data exfiltration: GCS bucket ACL set to public or broad access followed by high-volume object reads — active data staging for exfiltration.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 96,
        "resource": "gcs_bucket",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "setIamPermissions"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "storage.objects.get"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.correlation.lateral_movement_chain",
        "service": "ciem", "severity": "high",
        "check_type": "log_correlation",
        "title": "GCP: Lateral Movement Chain — SA Key Creation + Cross-Project Impersonation",
        "description": "Correlated lateral movement: service account key created followed by token generation for a different service account — key-based pivot to higher-privileged identity.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement", "privilege_escalation"],
        "mitre_techniques": ["T1548", "T1136.003"],
        "risk_score": 88,
        "resource": "service_account",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "CreateServiceAccountKey"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "GenerateAccessToken"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.correlation.supply_chain_attack",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP: Supply Chain Attack — Function Update + IAM Policy Grant",
        "description": "Correlated supply chain attack: Cloud Function or Cloud Run service updated followed by IAM role grant — compromised workload acquiring persistent elevated permissions.",
        "threat_category": "supply_chain_compromise",
        "mitre_tactics": ["execution", "privilege_escalation"],
        "mitre_techniques": ["T1648", "T1098.003"],
        "risk_score": 94,
        "resource": "cloud_function",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "in", "value": ["cloudfunctions.googleapis.com", "run.googleapis.com"]},
                    {"field": "operation",   "op": "in", "value": ["UpdateFunction", "ReplaceService"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
                    {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
                ]}},
            ],
        },
    },

    # ── IAM expansions ──────────────────────────────────────────────────────
    {
        "rule_id": "gcp.iam.audit.service_account_key_create",
        "service": "iam", "severity": "high",
        "title": "GCP IAM: Service Account Key Created",
        "description": "A new service account key was created. Keys are long-lived credentials that can be exported and reused outside GCP; prefer short-lived tokens via Workload Identity.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 78,
        "resource": "gcp_iam_service_account_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.admin.v1.CreateServiceAccountKey"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.service_account_key_delete",
        "service": "iam", "severity": "medium",
        "title": "GCP IAM: Service Account Key Deleted",
        "description": "A service account key was deleted. This may indicate an attacker covering tracks or disrupting legitimate access.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1070"],
        "risk_score": 62,
        "resource": "gcp_iam_service_account_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.admin.v1.DeleteServiceAccountKey"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.workload_identity_pool_create",
        "service": "iam", "severity": "high",
        "title": "GCP IAM: Workload Identity Pool Created",
        "description": "A Workload Identity Pool was created, allowing external identities to impersonate service accounts. Misconfigured pools can permit unauthorized cross-cloud access.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access", "privilege_escalation"],
        "mitre_techniques": ["T1078"],
        "risk_score": 80,
        "resource": "gcp_iam_workload_identity_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPool"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.service_account_impersonation",
        "service": "iam", "severity": "critical",
        "title": "GCP IAM: Service Account Impersonation via generateAccessToken",
        "description": "A principal generated a short-lived token by impersonating a service account. Attackers use impersonation to escalate to higher-privileged service accounts.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 92,
        "resource": "gcp_iam_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["GenerateAccessToken", "GenerateIdToken", "SignBlob", "SignJwt"]},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.allusers_binding_added",
        "service": "iam", "severity": "critical",
        "title": "GCP IAM: allUsers or allAuthenticatedUsers Binding Added",
        "description": "An IAM policy binding was added for allUsers or allAuthenticatedUsers, making a resource publicly accessible.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration", "initial_access"],
        "mitre_techniques": ["T1530"],
        "risk_score": 98,
        "resource": "gcp_iam_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
            {"field": "request.policy.bindings.members", "op": "contains_any", "value": ["allUsers", "allAuthenticatedUsers"]},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.custom_role_create",
        "service": "iam", "severity": "high",
        "title": "GCP IAM: Custom Role with Sensitive Permissions Created",
        "description": "A custom IAM role was created. Custom roles with overly broad permissions can bypass least-privilege controls.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 75,
        "resource": "gcp_iam_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.iam.admin.v1.CreateRole", "google.iam.admin.v1.UpdateRole"]},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.organization_policy_modified",
        "service": "iam", "severity": "critical",
        "title": "GCP IAM: Organization Policy Modified",
        "description": "An Organization Policy constraint was modified. Attackers with org-level access may remove security constraints to enable further exploitation.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 95,
        "resource": "gcp_organization_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "orgpolicy.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["UpdatePolicy", "DeletePolicy", "CreatePolicy"]},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.domain_wide_delegation_granted",
        "service": "iam", "severity": "critical",
        "title": "GCP IAM: Domain-Wide Delegation Granted to Service Account",
        "description": "Domain-wide delegation was granted to a service account, allowing it to impersonate any user in the Google Workspace domain.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "credential_access"],
        "mitre_techniques": ["T1098"],
        "risk_score": 97,
        "resource": "gcp_iam_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.admin.v1.UpdateServiceAccount"},
            {"field": "request.updateMask", "op": "contains", "value": "oauth2ClientId"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.sa_disabled",
        "service": "iam", "severity": "high",
        "title": "GCP IAM: Service Account Disabled",
        "description": "A service account was disabled. An attacker may disable production service accounts to cause service disruption or cover lateral movement.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 74,
        "resource": "gcp_iam_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.admin.v1.DisableServiceAccount"},
        ]}},
    },
    {
        "rule_id": "gcp.iam.audit.sa_delete",
        "service": "iam", "severity": "high",
        "title": "GCP IAM: Service Account Deleted",
        "description": "A service account was deleted. Deletion of service accounts used by workloads can cause outages and is a common impact technique.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 80,
        "resource": "gcp_iam_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "iam.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.admin.v1.DeleteServiceAccount"},
        ]}},
    },

    # ── Compute expansions ───────────────────────────────────────────────────
    {
        "rule_id": "gcp.compute.audit.firewall_rule_created",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: Firewall Rule Created",
        "description": "A new VPC firewall rule was created. Overly permissive rules (0.0.0.0/0 ingress) allow lateral movement or direct internet access.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "gcp_compute_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.firewalls.insert"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.firewall_rule_deleted",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: Firewall Rule Deleted",
        "description": "A VPC firewall rule was deleted. Removal of deny rules may open previously blocked traffic paths.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 82,
        "resource": "gcp_compute_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.firewalls.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.ssh_key_added_to_instance",
        "service": "compute", "severity": "critical",
        "title": "GCP Compute: SSH Key Added to Instance Metadata",
        "description": "An SSH key was injected into instance metadata, granting persistent SSH access to the VM.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1098"],
        "risk_score": 90,
        "resource": "gcp_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata"]},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.startup_script_modified",
        "service": "compute", "severity": "critical",
        "title": "GCP Compute: Instance Startup Script Modified",
        "description": "A VM instance startup-script was modified via metadata update. Startup scripts run as root at boot and are a powerful persistence mechanism.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "execution"],
        "mitre_techniques": ["T1037"],
        "risk_score": 93,
        "resource": "gcp_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.instances.setMetadata"},
            {"field": "request.items.key", "op": "contains", "value": "startup-script"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.snapshot_created",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: Disk Snapshot Created",
        "description": "A disk snapshot was created. Adversaries create disk snapshots to exfiltrate data by restoring snapshots outside the organization.",
        "threat_category": "collection",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1005"],
        "risk_score": 72,
        "resource": "gcp_compute_snapshot",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.disks.createSnapshot"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.snapshot_exported",
        "service": "compute", "severity": "critical",
        "title": "GCP Compute: Disk Snapshot Exported to External Project",
        "description": "A compute disk snapshot was exported (SetIamPolicy granting external access). Data exfiltration via snapshot copy is a known GCP attack technique.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1537"],
        "risk_score": 95,
        "resource": "gcp_compute_snapshot",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.snapshots.setIamPolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.instance_deleted",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: VM Instance Deleted",
        "description": "A VM instance was deleted. Mass instance deletion is an impact technique used in ransomware or destructive attacks.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 78,
        "resource": "gcp_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.instances.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.serial_port_enabled",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: Serial Port Access Enabled on Instance",
        "description": "Serial port access was enabled on a VM instance. Serial port access bypasses network-level controls and can be used for backdoor access.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1098"],
        "risk_score": 80,
        "resource": "gcp_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.instances.setMetadata"},
            {"field": "request.items.key", "op": "equals", "value": "serial-port-enable"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.os_login_disabled",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: OS Login Disabled on Instance",
        "description": "OS Login was disabled on a VM. This removes centralized IAM-based SSH access control, falling back to metadata-managed SSH keys.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 75,
        "resource": "gcp_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.instances.setMetadata"},
            {"field": "request.items.key", "op": "equals", "value": "enable-oslogin"},
            {"field": "request.items.value", "op": "equals", "value": "false"},
        ]}},
    },
    {
        "rule_id": "gcp.compute.audit.vpc_route_created",
        "service": "compute", "severity": "high",
        "title": "GCP Compute: Custom VPC Route Created",
        "description": "A custom route was added to a VPC network. Adversaries inject routes to redirect traffic through attacker-controlled instances.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1557"],
        "risk_score": 76,
        "resource": "gcp_compute_route",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "v1.compute.routes.insert"},
        ]}},
    },

    # ── Storage expansions ──────────────────────────────────────────────────
    {
        "rule_id": "gcp.storage.audit.bucket_made_public",
        "service": "storage", "severity": "critical",
        "title": "GCP Storage: Bucket Made Publicly Accessible",
        "description": "A GCS bucket was made publicly accessible via allUsers or allAuthenticatedUsers IAM binding. This can expose sensitive data to the internet.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 98,
        "resource": "gcp_storage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.setIamPermissions"},
            {"field": "request.policy.bindings.members", "op": "contains_any", "value": ["allUsers", "allAuthenticatedUsers"]},
        ]}},
    },
    {
        "rule_id": "gcp.storage.audit.uniform_access_disabled",
        "service": "storage", "severity": "high",
        "title": "GCP Storage: Uniform Bucket-Level Access Disabled",
        "description": "Uniform bucket-level access was disabled on a GCS bucket, re-enabling ACL-based permissions that can be harder to audit.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 72,
        "resource": "gcp_storage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.buckets.update"},
            {"field": "request.iamConfiguration.uniformBucketLevelAccess.enabled", "op": "equals", "value": False},
        ]}},
    },
    {
        "rule_id": "gcp.storage.audit.hmac_key_created",
        "service": "storage", "severity": "high",
        "title": "GCP Storage: HMAC Key Created for Service Account",
        "description": "An HMAC key was created for a GCS service account. HMAC keys are long-lived credentials used for S3-compatible access and can be exported.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 76,
        "resource": "gcp_storage_hmac_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.hmacKeys.create"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.audit.bucket_deleted",
        "service": "storage", "severity": "high",
        "title": "GCP Storage: Bucket Deleted",
        "description": "A GCS bucket was deleted. Bucket deletion is irreversible without versioning and may represent data destruction in a destructive attack.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "gcp_storage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.buckets.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.storage.audit.retention_policy_deleted",
        "service": "storage", "severity": "critical",
        "title": "GCP Storage: Bucket Retention Policy Deleted",
        "description": "A retention policy was removed from a GCS bucket. This allows objects to be deleted before their retention period and may be part of a data destruction attack.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 90,
        "resource": "gcp_storage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.buckets.update"},
            {"field": "request.retentionPolicy", "op": "equals", "value": None},
        ]}},
    },
    {
        "rule_id": "gcp.storage.audit.bucket_versioning_disabled",
        "service": "storage", "severity": "medium",
        "title": "GCP Storage: Bucket Versioning Disabled",
        "description": "Object versioning was disabled on a GCS bucket. Without versioning, deleted or overwritten objects cannot be recovered.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 65,
        "resource": "gcp_storage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "storage.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "storage.buckets.update"},
            {"field": "request.versioning.enabled", "op": "equals", "value": False},
        ]}},
    },

    # ── GKE/Container expansions ────────────────────────────────────────────
    {
        "rule_id": "gcp.container.audit.legacy_abac_enabled",
        "service": "container", "severity": "critical",
        "title": "GKE: Legacy ABAC Enabled on Cluster",
        "description": "Legacy Attribute-Based Access Control was enabled on a GKE cluster. Legacy ABAC grants the default service account broad cluster privileges.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 90,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.container.v1.ClusterManager.CreateCluster", "google.container.v1.ClusterManager.UpdateCluster"]},
            {"field": "request.cluster.legacyAbac.enabled", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.basic_auth_enabled",
        "service": "container", "severity": "critical",
        "title": "GKE: Basic Authentication Enabled on Cluster",
        "description": "Username/password basic authentication was enabled on a GKE cluster's Kubernetes API. Basic auth credentials can be brute-forced or leaked.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1078"],
        "risk_score": 92,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.container.v1.ClusterManager.CreateCluster", "google.container.v1.ClusterManager.SetMasterAuth"]},
            {"field": "request.masterAuth.username", "op": "not_equals", "value": ""},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.private_cluster_disabled",
        "service": "container", "severity": "high",
        "title": "GKE: Private Cluster Nodes Disabled",
        "description": "A GKE cluster was configured without private nodes, exposing nodes to public internet. Public nodes expand attack surface for container escape to host.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 80,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.container.v1.ClusterManager.CreateCluster"},
            {"field": "request.cluster.privateClusterConfig.enablePrivateNodes", "op": "equals", "value": False},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.audit_logging_disabled",
        "service": "container", "severity": "high",
        "title": "GKE: Audit Logging Disabled on Cluster",
        "description": "Cloud Audit Logging was disabled for a GKE cluster. Without audit logs, malicious API calls inside the cluster cannot be investigated.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 82,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.container.v1.ClusterManager.CreateCluster", "google.container.v1.ClusterManager.UpdateCluster"]},
            {"field": "request.cluster.loggingConfig.componentConfig.enableComponents", "op": "not_contains", "value": "SYSTEM_COMPONENTS"},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.node_pool_autoupgrade_disabled",
        "service": "container", "severity": "medium",
        "title": "GKE: Node Pool Auto-Upgrade Disabled",
        "description": "Auto-upgrade was disabled for a GKE node pool. Unpatched nodes accumulate CVEs over time.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 60,
        "resource": "gcp_container_node_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.container.v1.ClusterManager.CreateNodePool", "google.container.v1.ClusterManager.UpdateNodePool"]},
            {"field": "request.nodePool.management.autoUpgrade", "op": "equals", "value": False},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.workload_identity_disabled",
        "service": "container", "severity": "high",
        "title": "GKE: Workload Identity Disabled on Cluster",
        "description": "Workload Identity was not enabled on the GKE cluster. Without Workload Identity, pods can use the node's service account key to impersonate any service account.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 75,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.container.v1.ClusterManager.CreateCluster"},
            {"field": "request.cluster.workloadIdentityConfig", "op": "equals", "value": None},
        ]}},
    },
    {
        "rule_id": "gcp.container.audit.cluster_deleted",
        "service": "container", "severity": "critical",
        "title": "GKE: Cluster Deleted",
        "description": "A GKE cluster was deleted. Cluster deletion is a destructive impact action that terminates all workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "gcp_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "container.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.container.v1.ClusterManager.DeleteCluster"},
        ]}},
    },

    # ── Logging/Monitoring ──────────────────────────────────────────────────
    {
        "rule_id": "gcp.logging.audit.log_sink_deleted",
        "service": "logging", "severity": "high",
        "title": "GCP Logging: Log Sink Deleted",
        "description": "A log sink was deleted, stopping export of audit logs to a SIEM or storage. Adversaries delete sinks to blind defenders.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 85,
        "resource": "gcp_logging_sink",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.logging.v2.ConfigServiceV2.DeleteSink"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.audit.log_bucket_deleted",
        "service": "logging", "severity": "critical",
        "title": "GCP Logging: Log Bucket Deleted",
        "description": "A Cloud Logging log bucket was deleted, permanently removing stored log data. This may be evidence tampering.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1070"],
        "risk_score": 90,
        "resource": "gcp_logging_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.logging.v2.ConfigServiceV2.DeleteBucket"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.audit.audit_config_deleted",
        "service": "logging", "severity": "critical",
        "title": "GCP Logging: Audit Config Deleted",
        "description": "Cloud Audit configuration was removed, stopping data/admin activity logging for a service. Attackers disable audit configs before performing unauthorized operations.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 93,
        "resource": "gcp_logging_audit_config",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.logging.v2.ConfigServiceV2.UpdateBucket"},
            {"field": "request.updateMask", "op": "contains", "value": "locked"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.audit.metric_alert_deleted",
        "service": "logging", "severity": "high",
        "title": "GCP Logging: Log-Based Metric Alert Policy Deleted",
        "description": "An alerting policy based on log-based metrics was deleted, disabling security alerts for specific log events.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "gcp_monitoring_alert_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "monitoring.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.monitoring.v3.AlertPolicyService.DeleteAlertPolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.logging.audit.access_transparency_disabled",
        "service": "logging", "severity": "high",
        "title": "GCP Logging: Access Transparency Disabled",
        "description": "Access Transparency logging was disabled, removing visibility into Google staff access to customer data.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 70,
        "resource": "gcp_logging_access_transparency",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "accessapproval.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.accessapproval.v1.AccessApproval.DeleteAccessApprovalSettings"},
        ]}},
    },

    # ── BigQuery ─────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.bigquery.audit.dataset_made_public",
        "service": "bigquery", "severity": "critical",
        "title": "BigQuery: Dataset Made Publicly Accessible",
        "description": "A BigQuery dataset was made publicly accessible. This exposes potentially sensitive analytics data to anyone on the internet.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 97,
        "resource": "gcp_bigquery_dataset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.v1.IAMPolicy.SetIamPolicy"},
            {"field": "request.policy.bindings.members", "op": "contains_any", "value": ["allUsers", "allAuthenticatedUsers"]},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.audit.table_data_export",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Large Table Export to External Storage",
        "description": "A BigQuery table was exported to an external GCS bucket or location. Bulk data exports can be a data exfiltration vector.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1537"],
        "risk_score": 80,
        "resource": "gcp_bigquery_table",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.bigquery.v2.JobService.InsertJob"},
            {"field": "request.job.configuration.extract", "op": "exists", "value": True},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.audit.dataset_deleted",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Dataset Deleted",
        "description": "A BigQuery dataset was deleted. Dataset deletion removes all tables and is irreversible without backups.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "gcp_bigquery_dataset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.bigquery.v2.DatasetService.DeleteDataset"},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.audit.cmek_disabled",
        "service": "bigquery", "severity": "high",
        "title": "BigQuery: Customer-Managed Encryption Key Removed",
        "description": "Customer-managed encryption (CMEK) was removed from a BigQuery dataset, reverting to Google-managed keys.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 72,
        "resource": "gcp_bigquery_dataset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.bigquery.v2.DatasetService.UpdateDataset"},
            {"field": "request.dataset.defaultEncryptionConfiguration", "op": "equals", "value": None},
        ]}},
    },
    {
        "rule_id": "gcp.bigquery.audit.public_query",
        "service": "bigquery", "severity": "medium",
        "title": "BigQuery: Query Executed Against Public Dataset by Unknown Principal",
        "description": "A query job was executed against a public BigQuery dataset by an external/unrecognized principal, potentially enumerating data.",
        "threat_category": "discovery",
        "mitre_tactics": ["discovery"],
        "mitre_techniques": ["T1526"],
        "risk_score": 58,
        "resource": "gcp_bigquery_table",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "bigquery.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.bigquery.v2.JobService.InsertJob"},
            {"field": "authenticationInfo.principalEmail", "op": "not_contains", "value": ".gserviceaccount.com"},
        ]}},
    },

    # ── Cloud SQL ───────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.sql.audit.instance_public_ip_enabled",
        "service": "sql", "severity": "critical",
        "title": "Cloud SQL: Public IP Enabled on Instance",
        "description": "A Cloud SQL instance was configured with a public IP address. Publicly accessible databases should always require SSL and authorised networks.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 88,
        "resource": "gcp_sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudsql.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["cloudsql.instances.create", "cloudsql.instances.update"]},
            {"field": "request.ipConfiguration.ipv4Enabled", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "gcp.sql.audit.ssl_disabled",
        "service": "sql", "severity": "high",
        "title": "Cloud SQL: SSL Requirement Disabled",
        "description": "SSL was disabled for a Cloud SQL instance, allowing unencrypted connections that can be intercepted.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1040"],
        "risk_score": 80,
        "resource": "gcp_sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudsql.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["cloudsql.instances.create", "cloudsql.instances.update"]},
            {"field": "request.settings.ipConfiguration.requireSsl", "op": "equals", "value": False},
        ]}},
    },
    {
        "rule_id": "gcp.sql.audit.instance_deleted",
        "service": "sql", "severity": "high",
        "title": "Cloud SQL: Database Instance Deleted",
        "description": "A Cloud SQL instance was deleted. Without backups, this action results in permanent data loss.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 88,
        "resource": "gcp_sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudsql.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "cloudsql.instances.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.sql.audit.backup_disabled",
        "service": "sql", "severity": "high",
        "title": "Cloud SQL: Automated Backups Disabled",
        "description": "Automated backups were disabled on a Cloud SQL instance. Without backups, database recovery after destruction is impossible.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 78,
        "resource": "gcp_sql_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudsql.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["cloudsql.instances.create", "cloudsql.instances.update"]},
            {"field": "request.settings.backupConfiguration.enabled", "op": "equals", "value": False},
        ]}},
    },
    {
        "rule_id": "gcp.sql.audit.root_user_password_changed",
        "service": "sql", "severity": "critical",
        "title": "Cloud SQL: Root User Password Changed",
        "description": "The root database user password was changed on a Cloud SQL instance. Unauthorized root password changes grant full database access to attackers.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access", "persistence"],
        "mitre_techniques": ["T1098"],
        "risk_score": 93,
        "resource": "gcp_sql_user",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudsql.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "cloudsql.users.update"},
            {"field": "request.name", "op": "equals", "value": "root"},
        ]}},
    },

    # ── KMS ─────────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.kms.audit.key_destroyed",
        "service": "kms", "severity": "critical",
        "title": "GCP KMS: Cryptographic Key Destroyed",
        "description": "A Cloud KMS key version was scheduled for destruction or destroyed. This renders encrypted data permanently inaccessible and is a critical impact event.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "risk_score": 98,
        "resource": "gcp_kms_crypto_key_version",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "in", "value": [
                "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
                "google.cloud.kms.v1.KeyManagementService.ScheduleDestroyKeyVersion",
            ]},
        ]}},
    },
    {
        "rule_id": "gcp.kms.audit.key_disabled",
        "service": "kms", "severity": "high",
        "title": "GCP KMS: Cryptographic Key Disabled",
        "description": "A Cloud KMS key version was disabled. Disabling keys used by running workloads causes decryption failures and service outages.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 85,
        "resource": "gcp_kms_crypto_key_version",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion"},
            {"field": "request.cryptoKeyVersion.state", "op": "equals", "value": "DISABLED"},
        ]}},
    },
    {
        "rule_id": "gcp.kms.audit.keyring_iam_modified",
        "service": "kms", "severity": "high",
        "title": "GCP KMS: KeyRing IAM Policy Modified",
        "description": "The IAM policy on a Cloud KMS keyring was modified. Granting decrypt permissions to external identities allows key material misuse.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 80,
        "resource": "gcp_kms_key_ring",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudkms.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.v1.IAMPolicy.SetIamPolicy"},
        ]}},
    },

    # ── Secret Manager ──────────────────────────────────────────────────────
    {
        "rule_id": "gcp.secretmanager.audit.secret_accessed",
        "service": "secretmanager", "severity": "high",
        "title": "GCP Secret Manager: Secret Version Accessed",
        "description": "A secret version was accessed (accessed/payload retrieved). Unusual access patterns may indicate credential theft.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 75,
        "resource": "gcp_secretmanager_secret_version",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"},
        ]}},
    },
    {
        "rule_id": "gcp.secretmanager.audit.secret_deleted",
        "service": "secretmanager", "severity": "high",
        "title": "GCP Secret Manager: Secret Deleted",
        "description": "A secret and all its versions were deleted. Deletion of secrets used by workloads causes authentication failures.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 82,
        "resource": "gcp_secretmanager_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret"},
        ]}},
    },
    {
        "rule_id": "gcp.secretmanager.audit.replication_policy_changed",
        "service": "secretmanager", "severity": "medium",
        "title": "GCP Secret Manager: Secret Replication Policy Changed",
        "description": "A secret's replication policy was changed, potentially restricting availability or moving data to an unintended region.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 58,
        "resource": "gcp_secretmanager_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "secretmanager.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.secretmanager.v1.SecretManagerService.UpdateSecret"},
        ]}},
    },

    # ── Cloud Build ─────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.cloudbuild.audit.build_triggered_from_external_source",
        "service": "cloudbuild", "severity": "high",
        "title": "Cloud Build: Build Triggered from Unverified External Source",
        "description": "A Cloud Build was triggered from an external or unrecognized source repository. Supply chain attacks inject malicious code into CI/CD pipelines.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "initial_access"],
        "mitre_techniques": ["T1195"],
        "risk_score": 80,
        "resource": "gcp_cloudbuild_build",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudbuild.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"},
        ]}},
    },
    {
        "rule_id": "gcp.cloudbuild.audit.substitution_override",
        "service": "cloudbuild", "severity": "high",
        "title": "Cloud Build: Build Variables Overridden via Substitutions",
        "description": "Build substitution variables were overridden at trigger time. Attackers can override environment-defining variables to redirect builds to malicious artifacts.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1059"],
        "risk_score": 72,
        "resource": "gcp_cloudbuild_build",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudbuild.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.devtools.cloudbuild.v1.CloudBuild.RunBuildTrigger"},
            {"field": "request.substitutions", "op": "exists", "value": True},
        ]}},
    },
    {
        "rule_id": "gcp.cloudbuild.audit.worker_pool_created",
        "service": "cloudbuild", "severity": "medium",
        "title": "Cloud Build: Private Worker Pool Created",
        "description": "A Cloud Build private worker pool was created. Worker pools with excessive VPC access can be used to pivot from build environments into production networks.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1021"],
        "risk_score": 62,
        "resource": "gcp_cloudbuild_worker_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudbuild.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.devtools.cloudbuild.v1.CloudBuild.CreateWorkerPool"},
        ]}},
    },

    # ── Artifact Registry ───────────────────────────────────────────────────
    {
        "rule_id": "gcp.artifactregistry.audit.repository_made_public",
        "service": "artifactregistry", "severity": "high",
        "title": "Artifact Registry: Repository Made Publicly Readable",
        "description": "An Artifact Registry repository was made publicly readable. Publicly exposed registries may leak internal container images, including embedded secrets.",
        "threat_category": "collection",
        "mitre_tactics": ["collection"],
        "mitre_techniques": ["T1005"],
        "risk_score": 78,
        "resource": "gcp_artifactregistry_repository",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "artifactregistry.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.devtools.artifactregistry.v1.ArtifactRegistry.SetIamPolicy"},
            {"field": "request.policy.bindings.members", "op": "contains_any", "value": ["allUsers", "allAuthenticatedUsers"]},
        ]}},
    },
    {
        "rule_id": "gcp.artifactregistry.audit.image_deleted",
        "service": "artifactregistry", "severity": "high",
        "title": "Artifact Registry: Container Image Deleted",
        "description": "A container image or package version was deleted from Artifact Registry. Deletion of production images can break deployments.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 78,
        "resource": "gcp_artifactregistry_docker_image",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "artifactregistry.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.devtools.artifactregistry.v1.ArtifactRegistry.DeleteVersion", "google.devtools.artifactregistry.v1.ArtifactRegistry.DeletePackage"]},
        ]}},
    },
    {
        "rule_id": "gcp.artifactregistry.audit.vulnerability_scanning_disabled",
        "service": "artifactregistry", "severity": "medium",
        "title": "Artifact Registry: Vulnerability Scanning Disabled",
        "description": "Container vulnerability scanning was disabled on an Artifact Registry repository, allowing vulnerable images to be deployed without detection.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 65,
        "resource": "gcp_artifactregistry_repository",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "artifactregistry.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.devtools.artifactregistry.v1.ArtifactRegistry.UpdateRepository"},
        ]}},
    },

    # ── Binary Authorization ────────────────────────────────────────────────
    {
        "rule_id": "gcp.binaryauthorization.audit.policy_modified",
        "service": "binaryauthorization", "severity": "critical",
        "title": "Binary Authorization: Policy Modified to Allow Unverified Images",
        "description": "The Binary Authorization policy was modified. Weakening the policy allows unverified container images to be deployed to GKE.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 90,
        "resource": "gcp_binaryauthorization_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "binaryauthorization.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.binaryauthorization.v1.BinaryAuthorization.UpdatePolicy"},
        ]}},
    },
    {
        "rule_id": "gcp.binaryauthorization.audit.attestor_deleted",
        "service": "binaryauthorization", "severity": "high",
        "title": "Binary Authorization: Attestor Deleted",
        "description": "A Binary Authorization attestor was deleted, removing a software supply chain control that validates image integrity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 82,
        "resource": "gcp_binaryauthorization_attestor",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "binaryauthorization.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.binaryauthorization.v1.BinaryAuthorization.DeleteAttestor"},
        ]}},
    },

    # ── Cloud DNS ───────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.dns.audit.managed_zone_deleted",
        "service": "dns", "severity": "high",
        "title": "Cloud DNS: Managed Zone Deleted",
        "description": "A Cloud DNS managed zone was deleted, removing all DNS records and potentially causing service outages.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1498"],
        "risk_score": 85,
        "resource": "gcp_dns_managed_zone",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "dns.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "dns.managedZones.delete"},
        ]}},
    },
    {
        "rule_id": "gcp.dns.audit.record_set_modified",
        "service": "dns", "severity": "high",
        "title": "Cloud DNS: DNS Record Modified",
        "description": "A DNS record was added, modified, or deleted in a Cloud DNS zone. Unauthorized DNS record changes are used for traffic hijacking and phishing.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement", "collection"],
        "mitre_techniques": ["T1557"],
        "risk_score": 80,
        "resource": "gcp_dns_resource_record_set",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "dns.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "dns.changes.create"},
        ]}},
    },

    # ── PubSub ───────────────────────────────────────────────────────────────
    {
        "rule_id": "gcp.pubsub.audit.subscription_created_external",
        "service": "pubsub", "severity": "high",
        "title": "Pub/Sub: Subscription Created with External Push Endpoint",
        "description": "A Pub/Sub push subscription was created with an external HTTPS endpoint. Attackers create external subscriptions to exfiltrate event streams.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1537"],
        "risk_score": 82,
        "resource": "gcp_pubsub_subscription",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "pubsub.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.pubsub.v1.Subscriber.CreateSubscription"},
            {"field": "request.pushConfig.pushEndpoint", "op": "exists", "value": True},
        ]}},
    },
    {
        "rule_id": "gcp.pubsub.audit.topic_iam_policy_modified",
        "service": "pubsub", "severity": "medium",
        "title": "Pub/Sub: Topic IAM Policy Modified",
        "description": "The IAM policy on a Pub/Sub topic was modified. Granting publish access to external identities may enable unauthorized event injection.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1078"],
        "risk_score": 65,
        "resource": "gcp_pubsub_topic",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "pubsub.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.iam.v1.IAMPolicy.SetIamPolicy"},
        ]}},
    },

    # ── SCC / Security Command Center ───────────────────────────────────────
    {
        "rule_id": "gcp.scc.audit.finding_muted",
        "service": "scc", "severity": "high",
        "title": "SCC: Security Finding Muted",
        "description": "A Security Command Center finding was muted. Mass muting of findings may indicate an attacker suppressing alerts about their own activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 80,
        "resource": "gcp_scc_finding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.cloud.securitycenter.v1.SecurityCenter.SetMute", "google.cloud.securitycenter.v1.SecurityCenter.BulkMuteFindings"]},
        ]}},
    },
    {
        "rule_id": "gcp.scc.audit.notification_config_deleted",
        "service": "scc", "severity": "high",
        "title": "SCC: Notification Config Deleted",
        "description": "An SCC notification configuration was deleted, stopping security alerts from being forwarded to Pub/Sub or SIEM.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "gcp_scc_notification_config",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "securitycenter.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.securitycenter.v1.SecurityCenter.DeleteNotificationConfig"},
        ]}},
    },

    # ── Identity Platform ───────────────────────────────────────────────────
    {
        "rule_id": "gcp.identityplatform.audit.mfa_disabled",
        "service": "identityplatform", "severity": "critical",
        "title": "Identity Platform: MFA Disabled for Tenant",
        "description": "Multi-factor authentication enforcement was disabled for an Identity Platform tenant, weakening account takeover protections.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1556"],
        "risk_score": 90,
        "resource": "gcp_identityplatform_tenant",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "identitytoolkit.googleapis.com"},
            {"field": "operation",   "op": "in", "value": ["google.cloud.identitytoolkit.admin.v2.ProjectConfigService.UpdateConfig", "google.cloud.identitytoolkit.admin.v2.TenantManagementService.UpdateTenant"]},
        ]}},
    },
    {
        "rule_id": "gcp.identityplatform.audit.allowed_domains_cleared",
        "service": "identityplatform", "severity": "high",
        "title": "Identity Platform: Allowed Domains List Cleared",
        "description": "The authorized domains list was cleared for Identity Platform. Without domain restrictions, any domain can be used for OAuth redirects.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1078"],
        "risk_score": 80,
        "resource": "gcp_identityplatform_config",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "identitytoolkit.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.identitytoolkit.admin.v2.ProjectConfigService.UpdateConfig"},
            {"field": "request.authorizedDomains", "op": "equals", "value": []},
        ]}},
    },

    # ── Resource Manager ────────────────────────────────────────────────────
    {
        "rule_id": "gcp.resourcemanager.audit.project_deleted",
        "service": "resourcemanager", "severity": "critical",
        "title": "GCP: Project Deleted",
        "description": "A GCP project was deleted. Project deletion removes all resources including data, VMs, and service configurations.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 98,
        "resource": "gcp_project",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "DeleteProject"},
        ]}},
    },
    {
        "rule_id": "gcp.resourcemanager.audit.folder_iam_modified",
        "service": "resourcemanager", "severity": "high",
        "title": "GCP: Folder IAM Policy Modified",
        "description": "The IAM policy on a GCP folder was modified. Folder-level IAM changes propagate to all projects and resources within the folder.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 85,
        "resource": "gcp_folder",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "gcp_audit"},
            {"field": "service",     "op": "equals", "value": "cloudresourcemanager.googleapis.com"},
            {"field": "operation",   "op": "equals", "value": "google.cloud.resourcemanager.v3.Folders.SetIamPolicy"},
        ]}},
    },

    # ── CIEM Correlation Chains ─────────────────────────────────────────────
    {
        "rule_id": "gcp.ciem.chain.privilege_escalation_via_sa_impersonation",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP CIEM: Privilege Escalation Chain via Service Account Impersonation",
        "description": "Detect the privilege escalation pattern: IAM role modified → service account impersonation (generateAccessToken) → high-privilege API call, indicating a multi-step privilege escalation attack.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 97,
        "resource": "gcp_iam_service_account",
        "check_config": {
            "type": "sequence",
            "window_seconds": 600,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "operation",   "op": "contains", "value": "SetIamPolicy"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "iamcredentials.googleapis.com"},
                    {"field": "operation",   "op": "equals", "value": "GenerateAccessToken"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "in", "value": ["cloudresourcemanager.googleapis.com", "iam.googleapis.com"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.chain.data_exfiltration_via_snapshot",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP CIEM: Data Exfiltration via Disk Snapshot Export",
        "description": "Detect data exfiltration pattern: disk snapshot created → snapshot IAM policy modified to external account → snapshot copy or image creation by external actor.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1537"],
        "risk_score": 98,
        "resource": "gcp_compute_snapshot",
        "check_config": {
            "type": "sequence",
            "window_seconds": 900,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
                    {"field": "operation",   "op": "equals", "value": "v1.compute.disks.createSnapshot"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "compute.googleapis.com"},
                    {"field": "operation",   "op": "equals", "value": "v1.compute.snapshots.setIamPolicy"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "gcp.ciem.chain.defense_evasion_log_destruction",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "GCP CIEM: Defense Evasion via Log Sink and Bucket Deletion",
        "description": "Detect a defensive evasion pattern: log sink deleted + log bucket deleted within a short window, indicating an attempt to destroy audit evidence.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1070"],
        "risk_score": 99,
        "resource": "gcp_logging_sink",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
                    {"field": "operation",   "op": "equals", "value": "google.logging.v2.ConfigServiceV2.DeleteSink"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "gcp_audit"},
                    {"field": "service",     "op": "equals", "value": "logging.googleapis.com"},
                    {"field": "operation",   "op": "equals", "value": "google.logging.v2.ConfigServiceV2.DeleteBucket"},
                ]}},
            ],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment helpers
# ─────────────────────────────────────────────────────────────────────────────

def _enrich(r: dict) -> dict:
    """Derive all metadata fields not explicitly set in the rule definition."""
    cat  = r.get("threat_category", "")
    tech = (r.get("mitre_techniques") or [""])[0]
    parent = tech.split(".")[0] if tech else ""

    r.setdefault("provider",      "gcp")
    r.setdefault("check_type",    "log")
    r.setdefault("source",        "default")
    r.setdefault("is_active",     True)
    r.setdefault("version",       "1.0")
    r.setdefault("log_source_type",  "gcp_audit")
    r.setdefault("domain",        DOMAIN_BY_CAT.get(cat, "configuration_and_change_management"))
    r.setdefault("action_category", ACTION_BY_CAT.get(cat, "modify"))
    r.setdefault("posture_category", POSTURE_BY_CAT.get(cat, "threat_posture"))

    # rationale
    rat = RATIONALE.get(tech) or RATIONALE.get(parent)
    if not rat:
        rat = (
            f"Adversaries abuse {r.get('service','this service')} operations to achieve "
            f"{cat.replace('_',' ')} in GCP environments. "
            "Detected via Cloud Admin Activity or Data Access audit logs."
        )
    r.setdefault("rationale", rat)

    # remediation
    r.setdefault("remediation", REMEDIATION.get(cat, REMEDIATION["defense_evasion"]))

    # references
    refs = REFERENCES.get(tech) or REFERENCES.get(parent) or [
        f"https://attack.mitre.org/techniques/{tech.replace('.','/')}/" if tech else
        "https://cloud.google.com/security/overview",
        "https://cloud.google.com/logging/docs/audit",
    ]
    r.setdefault("references", refs)

    # compliance
    r.setdefault("compliance_frameworks", COMPLIANCE.get(cat, {}))

    # threat_tags
    tags = list(r.get("mitre_techniques") or [])
    for t in (r.get("mitre_techniques") or []):
        p = t.split(".")[0]
        if p not in tags:
            tags.append(p)
    tags.append(cat)
    svc = r.get("service", "")
    if svc and svc not in tags:
        tags.append(svc)
    tags.append("gcp")
    r.setdefault("threat_tags", tags)

    # risk_indicators
    iam_cats = IAM_CATS
    r.setdefault("risk_indicators", {
        "actor_type":   "gcp_principal",
        "action_type":  ACTION_BY_CAT.get(cat, "write"),
        "target_type":  r.get("resource", "cloud_resource"),
        "blast_radius": "organization" if "org" in r.get("rule_id","") else "project",
        "stealth_risk": "critical" if r.get("risk_score",0) >= 90 else
                        "high"     if r.get("risk_score",0) >= 70 else "medium",
    })

    # iam_security
    is_iam = (cat in iam_cats or
              any(s in r.get("service","") for s in ("iam","identity","workload")) or
              "iam" in r.get("rule_id",""))
    iam_mods = []
    if is_iam:
        rid = r.get("rule_id","")
        if "role" in rid or "policy" in rid:        iam_mods.append("role_management")
        if "service_account" in rid:                iam_mods.append("least_privilege")
        if "workload" in rid or "federation" in rid: iam_mods.append("access_control")
        if "key" in rid:                             iam_mods.append("access_control")
        if not iam_mods:                             iam_mods = ["access_control"]
    r.setdefault("iam_security", {"applicable": is_iam, "modules": iam_mods})

    # data_security
    is_data = cat in DATA_CATS
    ds: dict = {"applicable": is_data}
    if is_data:
        ds["modules"]    = ["data_access_governance"]
        ds["categories"] = ["sensitive_data_access"]
        ds["priority"]   = "critical" if r.get("risk_score",0) >= 85 else "high"
        ds["impact"] = {
            "pci":   "PCI DSS Requirement 3.4 — Protect stored account data from unauthorized access",
            "gdpr":  "GDPR Article 32 — Appropriate technical measures to ensure data security",
            "hipaa": "§164.312(a)(1) — Implement technical security measures for unauthorized access",
        }
        ds["sensitive_data_context"] = (
            f"Unauthorized {cat.replace('_',' ')} on GCP {r.get('resource','resource')} "
            "must be detected to prevent: data loss, regulatory violations, and unauthorized "
            "exposure of sensitive and personal data."
        )
    r.setdefault("data_security", ds)

    return r


# ─────────────────────────────────────────────────────────────────────────────
# YAML writer  (same field order as AWS/Azure CIEM)
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    if "\n" in value:
        lines = value.rstrip("\n").split("\n")
        return "|\n" + "\n".join("  " + ln for ln in lines)
    if any(c in value for c in (':', '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_rule(r: dict) -> str:
    lines = []

    for f in ("rule_id","service","provider","check_type","severity"):
        if f in r:
            lines.append(f"{f}: {_yaml_str(str(r[f]))}")

    lines.append(f"title: {_yaml_str(r.get('title', r['rule_id']))}")
    lines.append(f"description: {_yaml_str(r.get('description',''))}")
    lines.append(f"rationale: {_yaml_str(r.get('rationale',''))}")

    if "threat_category" in r:
        lines.append(f"threat_category: {r['threat_category']}")

    lines.append("mitre_tactics:")
    for t in (r.get("mitre_tactics") or []):
        lines.append(f"- {t}")

    lines.append("mitre_techniques:")
    for t in (r.get("mitre_techniques") or []):
        lines.append(f"- {t}")

    lines.append(f"risk_score: {r.get('risk_score', 50)}")

    for f in ("resource","source","is_active"):
        if f in r:
            v = r[f]
            if isinstance(v, bool):
                lines.append(f"{f}: {'true' if v else 'false'}")
            else:
                lines.append(f"{f}: {_yaml_str(str(v))}")

    for f in ("domain","action_category","log_source_type","posture_category"):
        if r.get(f):
            lines.append(f"{f}: {_yaml_str(str(r[f]))}")

    tags = r.get("threat_tags") or []
    if tags:
        lines.append("threat_tags:")
        for t in tags:
            lines.append(f"- {t}")
    else:
        lines.append("threat_tags: []")

    ri = r.get("risk_indicators") or {}
    if ri:
        lines.append("risk_indicators:")
        for k, v in ri.items():
            lines.append(f"  {k}: {v}")

    iam = r.get("iam_security") or {}
    lines.append("iam_security:")
    lines.append(f"  applicable: {'true' if iam.get('applicable') else 'false'}")
    mods = iam.get("modules", [])
    if mods:
        lines.append("  modules:")
        for m in mods:
            lines.append(f"  - {m}")
    else:
        lines.append("  modules: []")

    ds = r.get("data_security") or {}
    lines.append("data_security:")
    lines.append(f"  applicable: {'true' if ds.get('applicable') else 'false'}")
    if ds.get("applicable"):
        for m in ds.get("modules", []):
            pass
        if ds.get("modules"):
            lines.append("  modules:")
            for m in ds["modules"]:
                lines.append(f"  - {m}")
        if ds.get("categories"):
            lines.append("  categories:")
            for c in ds["categories"]:
                lines.append(f"  - {c}")
        if "priority" in ds:
            lines.append(f"  priority: {ds['priority']}")
        impact = ds.get("impact", {})
        if impact:
            lines.append("  impact:")
            for k, v in impact.items():
                lines.append(f"    {k}: {_yaml_str(v)}")
        sc = ds.get("sensitive_data_context","")
        if sc:
            lines.append(f"  sensitive_data_context: {_yaml_str(sc)}")

    cf = r.get("compliance_frameworks") or {}
    if cf:
        lines.append("compliance_frameworks:")
        for fw, controls in cf.items():
            lines.append(f"  {fw}:")
            for c in (controls or []):
                lines.append(f"  - {c}")
    else:
        lines.append("compliance_frameworks: {}")

    # detection_events if present
    if r.get("detection_events"):
        lines.append("detection_events:")
        for de in r["detection_events"]:
            lines.append(f"- {_yaml_str(de)}")

    lines.append(f"remediation: {_yaml_str(r.get('remediation',''))}")

    refs = r.get("references") or []
    if refs:
        lines.append("references:")
        for ref in refs:
            lines.append(f"- {ref}")

    import yaml as _yaml
    cc_yaml = _yaml.dump(
        {"check_config": r.get("check_config", {})},
        default_flow_style=False, allow_unicode=True,
    ).rstrip()
    lines.append(cc_yaml)

    lines.append(f"version: '{r.get('version','1.0')}'")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    written = skipped = errors = 0

    for r in RULES:
        r = _enrich(dict(r))
        rule_id  = r["rule_id"]
        service  = r.get("service", "misc")
        filename = rule_id + ".yaml"
        out_path = OUT / service / filename

        if args.dry_run:
            print(f"  DRY  {out_path.relative_to(ROOT)}")
            written += 1
            continue

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(_dump_rule(r), encoding="utf-8")
            written += 1
        except Exception as exc:
            print(f"  ERROR  {rule_id}: {exc}")
            errors += 1

    print(f"\nGenerated : {written}")
    if skipped: print(f"Skipped   : {skipped}")
    if errors:  print(f"Errors    : {errors}")
    if args.dry_run: print("(dry-run)")


if __name__ == "__main__":
    main()
