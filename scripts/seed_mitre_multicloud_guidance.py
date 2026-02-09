#!/usr/bin/env python3
"""
Extend MITRE Technique Reference with Azure and GCP Guidance.

Updates detection_guidance and remediation_guidance JSONB to include
CSP-specific sections alongside existing AWS data:
  - detection_guidance.azure: {activity_logs, defender_alerts, sentinel_rules, data_sources}
  - detection_guidance.gcp:   {audit_logs, scc_findings, chronicle_rules, data_sources}
  - remediation_guidance.azure: {immediate, preventive, azure_services}
  - remediation_guidance.gcp:   {immediate, preventive, gcp_services}

Existing AWS data is preserved — we MERGE into the JSONB, never overwrite.

Usage:
    python scripts/seed_mitre_multicloud_guidance.py --dry-run
    python scripts/seed_mitre_multicloud_guidance.py
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List

import psycopg2
from psycopg2.extras import Json, RealDictCursor


def get_conn():
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        database=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "postgres"),
        password=os.getenv("THREAT_DB_PASSWORD", ""),
    )


# ── Multi-cloud guidance data ───────────────────────────────────────────────
# Structure per technique:
#   azure_detection:    {activity_logs, defender_alerts, sentinel_rules, data_sources}
#   azure_remediation:  {immediate, preventive, azure_services}
#   gcp_detection:      {audit_logs, scc_findings, chronicle_rules, data_sources}
#   gcp_remediation:    {immediate, preventive, gcp_services}

MULTICLOUD_GUIDANCE: Dict[str, Dict[str, Any]] = {

    # ── Critical Techniques ──────────────────────────────────────────────

    "T1190": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Web/sites/write", "Microsoft.Network/applicationGateways/write"],
            "defender_alerts": ["Suspicious incoming web traffic", "Web application firewall alert"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'publicIPAddresses'"],
            "data_sources": ["Azure Activity Logs", "Azure Defender", "NSG Flow Logs", "Application Gateway Logs"],
        },
        "azure_remediation": {
            "immediate": ["Enable Azure WAF on Application Gateway", "Configure NSG to restrict inbound traffic"],
            "preventive": ["Use Azure Front Door with WAF", "Enable DDoS Protection Standard", "Use Private Link for PaaS"],
            "azure_services": ["Azure WAF", "Azure Defender", "Azure Firewall", "DDoS Protection"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.firewalls.insert", "compute.instances.setMetadata"],
            "scc_findings": ["OPEN_FIREWALL", "PUBLIC_IP_ADDRESS"],
            "chronicle_rules": ["GCP Firewall Rule Created allowing 0.0.0.0/0"],
            "data_sources": ["Cloud Audit Logs", "VPC Flow Logs", "Cloud Armor Logs", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Configure Cloud Armor WAF policies", "Restrict firewall rules to specific CIDRs"],
            "preventive": ["Use Cloud IAP for web applications", "Enable Cloud Armor adaptive protection", "Use Private Google Access"],
            "gcp_services": ["Cloud Armor", "Cloud IAP", "VPC Firewall Rules", "Security Command Center"],
        },
    },

    "T1485": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Storage/storageAccounts/delete", "Microsoft.Sql/servers/databases/delete"],
            "defender_alerts": ["Unusual volume of deletion operations", "Mass delete of resources"],
            "sentinel_rules": ["AzureActivity | where OperationName endswith '/delete' | summarize count() by Caller"],
            "data_sources": ["Azure Activity Logs", "Azure Defender", "Storage Analytics Logs"],
        },
        "azure_remediation": {
            "immediate": ["Enable soft delete on Storage Accounts and Key Vault", "Enable Azure SQL long-term retention"],
            "preventive": ["Apply Resource Locks (CanNotDelete)", "Enable Azure Backup with immutable vaults", "RBAC least privilege on delete operations"],
            "azure_services": ["Azure Backup", "Resource Locks", "Soft Delete", "Azure Policy"],
        },
        "gcp_detection": {
            "audit_logs": ["storage.objects.delete", "cloudsql.instances.delete", "compute.instances.delete"],
            "scc_findings": ["DATA_DESTRUCTION"],
            "chronicle_rules": ["GCP mass deletion event from single principal"],
            "data_sources": ["Cloud Audit Logs", "SCC Findings", "Cloud Storage Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Enable Object Versioning on Cloud Storage buckets", "Enable Cloud SQL automated backups"],
            "preventive": ["Use Retention Policies with Bucket Lock", "Organization policies to restrict delete permissions", "Enable Cloud Storage Object Hold"],
            "gcp_services": ["Cloud Storage Versioning", "Bucket Lock", "Cloud SQL Backups", "Organization Policies"],
        },
    },

    "T1486": {
        "azure_detection": {
            "activity_logs": ["Microsoft.KeyVault/vaults/keys/encrypt", "Microsoft.Storage/storageAccounts/listKeys"],
            "defender_alerts": ["Ransomware indicators detected", "Suspicious KMS activity"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'encrypt' or OperationName contains 'listKeys'"],
            "data_sources": ["Azure Activity Logs", "Key Vault Diagnostic Logs", "Azure Defender"],
        },
        "azure_remediation": {
            "immediate": ["Verify Key Vault access policies", "Review customer-managed key assignments"],
            "preventive": ["Enable Key Vault soft delete and purge protection", "Azure Backup with immutable vaults", "Restrict Key Vault access via Private Endpoint"],
            "azure_services": ["Azure Key Vault", "Azure Backup", "Azure Defender for Key Vault"],
        },
        "gcp_detection": {
            "audit_logs": ["cloudkms.cryptoKeys.encrypt", "cloudkms.cryptoKeyVersions.create"],
            "scc_findings": ["KMS_KEY_ROTATION_DISABLED"],
            "chronicle_rules": ["GCP KMS unusual encryption activity"],
            "data_sources": ["Cloud Audit Logs", "Cloud KMS Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Review Cloud KMS key policies", "Verify key rotation is enabled"],
            "preventive": ["Enable automatic key rotation", "Use Cloud KMS with separation of duties", "Object Versioning as ransomware defense"],
            "gcp_services": ["Cloud KMS", "Cloud Storage Versioning", "VPC Service Controls"],
        },
    },

    "T1490": {
        "azure_detection": {
            "activity_logs": ["Microsoft.RecoveryServices/vaults/backupFabrics/operationResults/delete"],
            "defender_alerts": ["Backup deletion detected"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'backup' and OperationName endswith 'delete'"],
            "data_sources": ["Azure Activity Logs", "Azure Backup Logs"],
        },
        "azure_remediation": {
            "immediate": ["Enable soft delete for Azure Backup", "Review backup vault access policies"],
            "preventive": ["Enable immutable vaults for Azure Backup", "Use RBAC to restrict backup deletion", "Enable multi-user authorization for backup"],
            "azure_services": ["Azure Backup", "Immutable Vaults", "Multi-User Authorization"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.snapshots.delete", "cloudsql.backupRuns.delete"],
            "scc_findings": [],
            "chronicle_rules": ["GCP backup deletion by non-admin principal"],
            "data_sources": ["Cloud Audit Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Verify backup retention policies are enforced", "Review IAM for backup delete permissions"],
            "preventive": ["Use organization policies to restrict backup deletion", "Enable Cloud SQL PITR", "Use Bucket Lock for backup storage"],
            "gcp_services": ["Cloud SQL PITR", "Organization Policies", "Bucket Lock"],
        },
    },

    "T1537": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Storage/storageAccounts/blobServices/containers/write", "Microsoft.Compute/snapshots/write"],
            "defender_alerts": ["Cross-tenant data transfer detected"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'snapshot' and CallerIpAddress !startswith '10.'"],
            "data_sources": ["Azure Activity Logs", "Storage Analytics", "Azure Defender"],
        },
        "azure_remediation": {
            "immediate": ["Restrict cross-subscription snapshot sharing", "Audit SAS tokens on storage accounts"],
            "preventive": ["Azure Policy to deny cross-tenant resource sharing", "Use Private Endpoints for storage", "Enable Microsoft Defender for Storage"],
            "azure_services": ["Azure Policy", "Microsoft Defender for Storage", "Private Endpoints"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.images.setIamPolicy", "storage.buckets.setIamPolicy"],
            "scc_findings": ["PUBLIC_BUCKET_ACL"],
            "chronicle_rules": ["GCP cross-project resource sharing event"],
            "data_sources": ["Cloud Audit Logs", "SCC Findings", "IAM Recommender"],
        },
        "gcp_remediation": {
            "immediate": ["Review cross-project IAM bindings", "Audit bucket ACLs for allUsers/allAuthenticatedUsers"],
            "preventive": ["Use VPC Service Controls to restrict data egress", "Organization policies to restrict sharing", "Enable uniform bucket-level access"],
            "gcp_services": ["VPC Service Controls", "Organization Policies", "Uniform Bucket Access"],
        },
    },

    "T1562": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Insights/diagnosticSettings/delete", "Microsoft.Security/pricings/write"],
            "defender_alerts": ["Security monitoring disabled", "Diagnostic settings removed"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'diagnosticSettings/delete'"],
            "data_sources": ["Azure Activity Logs", "Azure Defender Alerts"],
        },
        "azure_remediation": {
            "immediate": ["Re-enable diagnostic settings", "Verify Azure Defender plans are active"],
            "preventive": ["Azure Policy to enforce diagnostic settings", "Resource Lock on monitoring resources", "Use Azure Lighthouse for cross-tenant monitoring"],
            "azure_services": ["Azure Monitor", "Azure Defender", "Azure Policy", "Resource Locks"],
        },
        "gcp_detection": {
            "audit_logs": ["logging.sinks.delete", "logging.exclusions.create", "securitycenter.sources.update"],
            "scc_findings": ["AUDIT_LOGGING_DISABLED"],
            "chronicle_rules": ["GCP audit logging disabled or exclusion created"],
            "data_sources": ["Cloud Audit Logs (Admin Activity)", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Re-enable audit logging", "Remove log exclusion filters"],
            "preventive": ["Organization policies to require audit logging", "Use log sinks to centralized SIEM", "Enable SCC Premium for threat detection"],
            "gcp_services": ["Cloud Logging", "Security Command Center", "Organization Policies"],
        },
    },

    "T1562.008": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Insights/logProfiles/delete", "Microsoft.OperationalInsights/workspaces/delete"],
            "defender_alerts": ["Log collection stopped"],
            "sentinel_rules": ["AzureActivity | where OperationName endswith 'logProfiles/delete'"],
            "data_sources": ["Azure Activity Logs"],
        },
        "azure_remediation": {
            "immediate": ["Re-enable activity log profile", "Verify Log Analytics workspace is collecting"],
            "preventive": ["Azure Policy to require diagnostic logging", "Send logs to immutable storage"],
            "azure_services": ["Azure Monitor", "Log Analytics", "Azure Policy"],
        },
        "gcp_detection": {
            "audit_logs": ["logging.sinks.delete", "logging.logEntries.delete"],
            "scc_findings": ["AUDIT_LOGGING_DISABLED"],
            "chronicle_rules": ["GCP Cloud Logging sink deleted"],
            "data_sources": ["Admin Activity Audit Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Restore logging sinks", "Verify _Default and _Required sinks exist"],
            "preventive": ["Lock logging sinks with organization policies", "Export to BigQuery for immutable retention"],
            "gcp_services": ["Cloud Logging", "BigQuery", "Organization Policies"],
        },
    },

    "T1531": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Authorization/roleAssignments/delete", "Microsoft.ManagedIdentity/userAssignedIdentities/delete"],
            "defender_alerts": ["Role assignment removed from critical resource"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'roleAssignments/delete'"],
            "data_sources": ["Azure Activity Logs", "Azure AD Audit Logs"],
        },
        "azure_remediation": {
            "immediate": ["Review recent role assignment changes", "Restore deleted managed identities"],
            "preventive": ["Use PIM for just-in-time access", "Azure AD access reviews", "Conditional Access policies"],
            "azure_services": ["Azure AD PIM", "Conditional Access", "Azure AD Access Reviews"],
        },
        "gcp_detection": {
            "audit_logs": ["iam.serviceAccounts.delete", "iam.roles.delete"],
            "scc_findings": [],
            "chronicle_rules": ["GCP service account or IAM role deleted"],
            "data_sources": ["Cloud Audit Logs", "IAM Recommender"],
        },
        "gcp_remediation": {
            "immediate": ["Review recently deleted service accounts (30-day undelete window)", "Audit IAM policy changes"],
            "preventive": ["Use organization policies to restrict SA deletion", "Enable Workload Identity for GKE"],
            "gcp_services": ["IAM", "Organization Policies", "Workload Identity"],
        },
    },

    "T1552.005": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Compute/virtualMachines/instanceView"],
            "defender_alerts": ["Instance metadata access from unusual source"],
            "sentinel_rules": ["AzureDiagnostics | where ResourceType == 'VIRTUALNETWORKS' and RequestUri contains '169.254.169.254'"],
            "data_sources": ["NSG Flow Logs", "VM Diagnostics"],
        },
        "azure_remediation": {
            "immediate": ["Restrict IMDS access with NSG rules", "Use managed identities instead of keys"],
            "preventive": ["Enable IMDSv2 equivalent (Trusted Launch)", "Use Azure Key Vault for secrets"],
            "azure_services": ["Managed Identity", "Azure Key Vault", "Trusted Launch"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.instances.getSerialPortOutput"],
            "scc_findings": ["COMPUTE_ENGINE_METADATA_SERVER_ATTACK"],
            "chronicle_rules": ["GCP metadata server access from unusual source"],
            "data_sources": ["VPC Flow Logs", "Compute Engine Logs", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Block metadata server access from unauthorized pods/VMs", "Review service account key usage"],
            "preventive": ["Use Workload Identity instead of metadata-based auth", "Enable OS Login for SSH", "Use VPC firewall rules to restrict metadata access"],
            "gcp_services": ["Workload Identity", "OS Login", "VPC Firewall Rules"],
        },
    },

    # ── High Techniques ──────────────────────────────────────────────────

    "T1078": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Authorization/roleAssignments/write"],
            "defender_alerts": ["Suspicious sign-in activity", "Impossible travel detected"],
            "sentinel_rules": ["SigninLogs | where ResultType == 0 and RiskLevel != 'none'"],
            "data_sources": ["Azure AD Sign-in Logs", "Azure AD Audit Logs", "Azure Defender"],
        },
        "azure_remediation": {
            "immediate": ["Reset compromised account credentials", "Revoke active sessions"],
            "preventive": ["Enforce MFA for all users", "Conditional Access policies", "Enable Azure AD Identity Protection"],
            "azure_services": ["Azure AD MFA", "Conditional Access", "Azure AD Identity Protection", "PIM"],
        },
        "gcp_detection": {
            "audit_logs": ["iam.serviceAccountKeys.create", "SetIamPolicy"],
            "scc_findings": ["SERVICE_ACCOUNT_KEY_NOT_ROTATED"],
            "chronicle_rules": ["GCP login from anomalous location", "Service account key created"],
            "data_sources": ["Cloud Audit Logs", "Workspace Login Audit", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Rotate compromised service account keys", "Disable compromised user accounts"],
            "preventive": ["Enforce 2-Step Verification", "Use Workload Identity instead of SA keys", "Enable Context-Aware Access"],
            "gcp_services": ["Cloud Identity", "Workload Identity", "BeyondCorp Enterprise", "IAM Recommender"],
        },
    },

    "T1098": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Authorization/roleAssignments/write", "Microsoft.ManagedIdentity/userAssignedIdentities/assign"],
            "defender_alerts": ["Privileged role assigned outside PIM", "New federation trust created"],
            "sentinel_rules": ["AuditLogs | where OperationName contains 'Add member to role'"],
            "data_sources": ["Azure AD Audit Logs", "Azure Activity Logs"],
        },
        "azure_remediation": {
            "immediate": ["Review all role assignments in last 24h", "Check for new federation trusts"],
            "preventive": ["Use PIM for all privileged roles", "Enable access reviews", "Restrict Global Admin count to ≤5"],
            "azure_services": ["Azure AD PIM", "Access Reviews", "Conditional Access"],
        },
        "gcp_detection": {
            "audit_logs": ["SetIamPolicy", "iam.serviceAccounts.create", "iam.roles.create"],
            "scc_findings": ["ADMIN_SERVICE_ACCOUNT", "OVER_PRIVILEGED_SERVICE_ACCOUNT"],
            "chronicle_rules": ["GCP IAM policy change granting Owner/Editor"],
            "data_sources": ["Cloud Audit Logs", "SCC Findings", "IAM Recommender"],
        },
        "gcp_remediation": {
            "immediate": ["Review IAM policy bindings for Owner/Editor roles", "Audit custom roles for excessive permissions"],
            "preventive": ["Use IAM Recommender to right-size permissions", "Organization policies to restrict role grants", "Enable Domain Restricted Sharing"],
            "gcp_services": ["IAM Recommender", "Organization Policies", "Policy Intelligence"],
        },
    },

    "T1530": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
            "defender_alerts": ["Anonymous access to storage account", "Unusual data transfer from storage"],
            "sentinel_rules": ["StorageBlobLogs | where AuthenticationType == 'Anonymous'"],
            "data_sources": ["Storage Analytics Logs", "Azure Defender for Storage", "NSG Flow Logs"],
        },
        "azure_remediation": {
            "immediate": ["Disable anonymous/public access on storage accounts", "Enable Azure Defender for Storage"],
            "preventive": ["Azure Policy to deny public blob access", "Use Private Endpoints", "Enable storage encryption with CMK"],
            "azure_services": ["Microsoft Defender for Storage", "Azure Policy", "Private Endpoints", "CMK Encryption"],
        },
        "gcp_detection": {
            "audit_logs": ["storage.objects.get", "storage.objects.list"],
            "scc_findings": ["PUBLIC_BUCKET_ACL", "BUCKET_POLICY_ONLY_DISABLED"],
            "chronicle_rules": ["GCP Storage bucket accessed from external IP"],
            "data_sources": ["Cloud Audit Logs", "Cloud Storage Logs", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Remove allUsers/allAuthenticatedUsers from bucket ACLs", "Enable uniform bucket-level access"],
            "preventive": ["Organization policy to restrict public bucket creation", "Use VPC Service Controls", "Enable CMEK encryption"],
            "gcp_services": ["SCC", "VPC Service Controls", "Uniform Bucket Access", "CMEK"],
        },
    },

    "T1496": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Compute/virtualMachines/write", "Microsoft.ContainerService/managedClusters/write"],
            "defender_alerts": ["Cryptocurrency mining detected", "Resource hijacking indicators"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'virtualMachines/write' and CallerIpAddress !in (known_ips)"],
            "data_sources": ["Azure Defender", "Azure Activity Logs", "VM Performance Metrics"],
        },
        "azure_remediation": {
            "immediate": ["Terminate unauthorized VMs/containers", "Rotate compromised credentials"],
            "preventive": ["Set spending alerts and budgets", "Azure Policy to restrict VM SKUs", "Enable JIT VM access"],
            "azure_services": ["Azure Cost Management", "Azure Policy", "JIT VM Access", "Azure Defender"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.instances.insert", "container.clusters.create"],
            "scc_findings": ["CRYPTOMINING_THREAT"],
            "chronicle_rules": ["GCP unusual VM creation in non-standard region"],
            "data_sources": ["Cloud Audit Logs", "SCC Premium", "Billing Alerts"],
        },
        "gcp_remediation": {
            "immediate": ["Delete unauthorized compute instances", "Revoke compromised service account keys"],
            "preventive": ["Set billing budgets and alerts", "Organization policy to restrict regions", "Quotas on compute resources"],
            "gcp_services": ["Billing Budgets", "Organization Policies", "Resource Quotas", "SCC Premium"],
        },
    },

    "T1199": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Subscription/CreateSubscription/action"],
            "defender_alerts": ["Suspicious cross-tenant activity"],
            "sentinel_rules": ["AzureActivity | where Authorization_d.scope contains '/providers/Microsoft.Management/managementGroups'"],
            "data_sources": ["Azure AD Audit Logs", "Azure Activity Logs"],
        },
        "azure_remediation": {
            "immediate": ["Review B2B/guest accounts and their permissions", "Audit cross-tenant access settings"],
            "preventive": ["Configure cross-tenant access policies", "Use Conditional Access for B2B", "Regular access reviews for guest accounts"],
            "azure_services": ["Cross-Tenant Access Settings", "Conditional Access", "Access Reviews"],
        },
        "gcp_detection": {
            "audit_logs": ["SetIamPolicy with cross-project principals"],
            "scc_findings": [],
            "chronicle_rules": ["GCP IAM binding from external organization"],
            "data_sources": ["Cloud Audit Logs", "Organization Policy Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Audit IAM bindings from external domains", "Review domain-restricted sharing policy"],
            "preventive": ["Enable Domain Restricted Sharing", "Use VPC Service Controls for data perimeter", "Organization policies to restrict external sharing"],
            "gcp_services": ["Domain Restricted Sharing", "VPC Service Controls", "Organization Policies"],
        },
    },

    "T1525": {
        "azure_detection": {
            "activity_logs": ["Microsoft.ContainerRegistry/registries/push", "Microsoft.Compute/images/write"],
            "defender_alerts": ["Suspicious container image pushed", "Vulnerable container image detected"],
            "sentinel_rules": ["ContainerRegistryLoginEvents | where OperationName == 'Push'"],
            "data_sources": ["Azure Container Registry Logs", "Azure Defender for Containers"],
        },
        "azure_remediation": {
            "immediate": ["Scan ACR images for vulnerabilities", "Review recent image pushes"],
            "preventive": ["Enable Azure Defender for container registries", "Use Content Trust for image signing", "ACR quarantine for new images"],
            "azure_services": ["Azure Defender for Containers", "Content Trust", "ACR Tasks"],
        },
        "gcp_detection": {
            "audit_logs": ["artifactregistry.repositories.uploadArtifacts"],
            "scc_findings": ["CONTAINER_VULNERABILITY"],
            "chronicle_rules": ["GCP Artifact Registry push from unauthorized source"],
            "data_sources": ["Cloud Audit Logs", "Artifact Analysis", "SCC Findings"],
        },
        "gcp_remediation": {
            "immediate": ["Scan container images with Artifact Analysis", "Review recent image pushes"],
            "preventive": ["Enable Binary Authorization", "Use Artifact Registry instead of Container Registry", "Vulnerability scanning on push"],
            "gcp_services": ["Binary Authorization", "Artifact Analysis", "Artifact Registry"],
        },
    },

    "T1556": {
        "azure_detection": {
            "activity_logs": ["Microsoft.AADDomainServices/domainServices/write"],
            "defender_alerts": ["Federation settings modified", "Authentication method changed"],
            "sentinel_rules": ["AuditLogs | where OperationName contains 'Set federation settings'"],
            "data_sources": ["Azure AD Audit Logs", "Azure AD Sign-in Logs"],
        },
        "azure_remediation": {
            "immediate": ["Review federation trust configurations", "Audit conditional access bypasses"],
            "preventive": ["Monitor federation settings changes", "Use Passwordless authentication", "Enable Azure AD Continuous Access Evaluation"],
            "azure_services": ["Azure AD", "Conditional Access", "Passwordless Auth", "CAE"],
        },
        "gcp_detection": {
            "audit_logs": ["admin.googleapis.com/AdminService/2StepVerification"],
            "scc_findings": ["MFA_NOT_ENFORCED"],
            "chronicle_rules": ["GCP Workspace 2FA settings changed"],
            "data_sources": ["Workspace Admin Audit", "Cloud Identity Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Review 2-Step Verification enforcement", "Audit SSO/SAML configurations"],
            "preventive": ["Enforce 2SV for all org members", "Use security keys for admins", "Enable Context-Aware Access"],
            "gcp_services": ["Cloud Identity", "BeyondCorp Enterprise", "Security Key Enforcement"],
        },
    },

    # ── Medium Techniques ────────────────────────────────────────────────

    "T1578": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/snapshots/write"],
            "defender_alerts": ["Unusual VM modification", "Snapshot created from unusual source"],
            "sentinel_rules": ["AzureActivity | where OperationName contains 'snapshots/write'"],
            "data_sources": ["Azure Activity Logs", "Azure Defender"],
        },
        "azure_remediation": {
            "immediate": ["Review recent VM and snapshot modifications", "Verify integrity of running instances"],
            "preventive": ["Azure Policy to restrict VM modifications", "Enable JIT VM access", "RBAC least privilege"],
            "azure_services": ["Azure Policy", "JIT VM Access", "Azure Defender for Servers"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.instances.insert", "compute.snapshots.create", "compute.images.create"],
            "scc_findings": [],
            "chronicle_rules": ["GCP snapshot or image created by non-admin"],
            "data_sources": ["Cloud Audit Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Review recent snapshot and image creation", "Audit compute instance modifications"],
            "preventive": ["Organization policies to restrict image creation", "Use Shielded VMs", "Enable OS Login"],
            "gcp_services": ["Shielded VMs", "OS Login", "Organization Policies"],
        },
    },

    "T1535": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Compute/virtualMachines/write in unusual region"],
            "defender_alerts": ["Resource created in unusual region"],
            "sentinel_rules": ["AzureActivity | where Resource contains 'virtualMachines' and Location !in (approved_regions)"],
            "data_sources": ["Azure Activity Logs"],
        },
        "azure_remediation": {
            "immediate": ["Audit resources in non-standard regions", "Delete unauthorized resources"],
            "preventive": ["Azure Policy to restrict allowed regions", "Spending alerts per region"],
            "azure_services": ["Azure Policy", "Cost Management"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.instances.insert in unusual region"],
            "scc_findings": [],
            "chronicle_rules": ["GCP resource creation in non-approved region"],
            "data_sources": ["Cloud Audit Logs", "Billing Reports"],
        },
        "gcp_remediation": {
            "immediate": ["Audit resources in non-standard regions", "Delete unauthorized resources"],
            "preventive": ["Organization policy to restrict allowed regions (constraints/gcp.resourceLocations)", "Billing budgets per project"],
            "gcp_services": ["Organization Policies", "Billing Budgets", "Resource Manager"],
        },
    },

    "T1110": {
        "azure_detection": {
            "activity_logs": [],
            "defender_alerts": ["Brute force attack detected", "Password spray attack"],
            "sentinel_rules": ["SigninLogs | where ResultType in ('50126', '50053') | summarize count() by IPAddress"],
            "data_sources": ["Azure AD Sign-in Logs", "Azure AD Identity Protection"],
        },
        "azure_remediation": {
            "immediate": ["Block source IPs", "Reset affected accounts", "Enable Smart Lockout"],
            "preventive": ["Enforce MFA", "Enable Azure AD Password Protection", "Use Conditional Access risk-based policies"],
            "azure_services": ["Azure AD Smart Lockout", "Password Protection", "Conditional Access", "Identity Protection"],
        },
        "gcp_detection": {
            "audit_logs": ["google.login.LoginService.loginFailure"],
            "scc_findings": [],
            "chronicle_rules": ["GCP multiple failed logins from single IP"],
            "data_sources": ["Workspace Login Audit", "Cloud Identity Logs"],
        },
        "gcp_remediation": {
            "immediate": ["Block source IPs via VPC firewall", "Reset compromised account passwords"],
            "preventive": ["Enforce 2-Step Verification", "Use security keys for all users", "Enable Login Challenge for suspicious logins"],
            "gcp_services": ["Cloud Identity", "reCAPTCHA Enterprise", "BeyondCorp"],
        },
    },

    "T1580": {
        "azure_detection": {
            "activity_logs": ["Microsoft.Resources/subscriptions/resources/read", "Microsoft.Authorization/permissions/read"],
            "defender_alerts": ["Unusual resource enumeration"],
            "sentinel_rules": ["AzureActivity | where OperationName contains '/read' | summarize count() by Caller | where count_ > 100"],
            "data_sources": ["Azure Activity Logs", "Azure AD Sign-in Logs"],
        },
        "azure_remediation": {
            "immediate": ["Review accounts with excessive read permissions", "Audit API call patterns"],
            "preventive": ["RBAC least privilege", "JIT access for read operations", "Disable unused Reader role assignments"],
            "azure_services": ["Azure RBAC", "PIM", "Azure Policy"],
        },
        "gcp_detection": {
            "audit_logs": ["compute.instances.list", "storage.buckets.list", "iam.serviceAccounts.list"],
            "scc_findings": [],
            "chronicle_rules": ["GCP excessive resource enumeration from single principal"],
            "data_sources": ["Cloud Audit Logs", "IAM Recommender"],
        },
        "gcp_remediation": {
            "immediate": ["Review service accounts with broad Viewer roles", "Audit excessive API call patterns"],
            "preventive": ["Use IAM Recommender to reduce permissions", "Organization policies to restrict API access", "Use VPC Service Controls"],
            "gcp_services": ["IAM Recommender", "VPC Service Controls", "Organization Policies"],
        },
    },
}


def update_guidance(conn, dry_run: bool = False):
    """Merge Azure/GCP guidance into existing detection_guidance and remediation_guidance."""
    updated = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for tech_id, data in MULTICLOUD_GUIDANCE.items():
            # Read current values
            cur.execute("""
                SELECT technique_id, detection_guidance, remediation_guidance
                FROM mitre_technique_reference
                WHERE technique_id = %s
            """, (tech_id,))
            row = cur.fetchone()
            if not row:
                print(f"  SKIP (not in DB): {tech_id}")
                continue

            # Merge detection_guidance
            det = row["detection_guidance"] or {}
            if "azure" not in det and "azure_detection" in data:
                det["azure"] = data["azure_detection"]
            if "gcp" not in det and "gcp_detection" in data:
                det["gcp"] = data["gcp_detection"]

            # Merge remediation_guidance
            rem = row["remediation_guidance"] or {}
            if "azure" not in rem and "azure_remediation" in data:
                rem["azure"] = data["azure_remediation"]
            if "gcp" not in rem and "gcp_remediation" in data:
                rem["gcp"] = data["gcp_remediation"]

            if dry_run:
                az_det = "✅" if "azure" in det else "❌"
                gcp_det = "✅" if "gcp" in det else "❌"
                print(f"  {tech_id}: Azure {az_det}  GCP {gcp_det}")
            else:
                cur.execute("""
                    UPDATE mitre_technique_reference
                    SET detection_guidance = %s,
                        remediation_guidance = %s,
                        updated_at = NOW()
                    WHERE technique_id = %s
                """, (Json(det), Json(rem), tech_id))
                print(f"  UPDATED: {tech_id}")

            updated += 1

    if not dry_run:
        conn.commit()

    return updated


def main():
    parser = argparse.ArgumentParser(description="Extend MITRE guidance with Azure/GCP")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    args = parser.parse_args()

    conn = get_conn()

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Extending MITRE guidance to Azure/GCP")
    print(f"Techniques: {len(MULTICLOUD_GUIDANCE)}")
    print(f"{'='*70}\n")

    updated = update_guidance(conn, args.dry_run)

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Done: {updated} techniques extended")
    print(f"{'='*70}\n")

    conn.close()


if __name__ == "__main__":
    main()
