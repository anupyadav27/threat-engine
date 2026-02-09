#!/usr/bin/env python3
"""
Extend MITRE Technique Reference with OCI, IBM Cloud, Alicloud, and K8s guidance.

Merges CSP-specific sections into existing detection_guidance and
remediation_guidance JSONB. Preserves existing AWS/Azure/GCP data.

Structure added per CSP:
  detection_guidance.{csp}:   {audit_logs/events, alert_key, rules, data_sources}
  remediation_guidance.{csp}: {immediate, preventive, services}

Usage:
    python scripts/seed_mitre_remaining_csp_guidance.py --dry-run
    python scripts/seed_mitre_remaining_csp_guidance.py
    python scripts/seed_mitre_remaining_csp_guidance.py --csp oci    # single CSP only
"""

import argparse
import os
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


# ─────────────────────────────────────────────────────────────────────────────
# Technique list: 20 most critical cloud techniques (superset of what rules use)
# We add guidance for each technique × each CSP.
# ─────────────────────────────────────────────────────────────────────────────

# ── OCI (Oracle Cloud Infrastructure) ────────────────────────────────────────

OCI_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "detection": {
            "audit_logs": ["com.oraclecloud.virtualnetwork.CreateSecurityList", "com.oraclecloud.loadbalancer.CreateLoadBalancer"],
            "cloud_guard_findings": ["SECURITY_LIST_OPEN_PORT", "PUBLIC_IP_ATTACHED"],
            "rules": ["OCI Audit | where eventName contains 'SecurityList' and target.publicIp != null"],
            "data_sources": ["OCI Audit Logs", "Cloud Guard Findings", "VCN Flow Logs"],
        },
        "remediation": {
            "immediate": ["Review Security Lists for 0.0.0.0/0 ingress rules", "Configure WAF on Load Balancers"],
            "preventive": ["Use Network Security Groups (NSGs) instead of Security Lists", "Enable OCI WAF", "Use Private Subnets with NAT Gateway"],
            "oci_services": ["OCI WAF", "Cloud Guard", "Network Security Groups", "Bastion Service"],
        },
    },
    "T1078": {
        "detection": {
            "audit_logs": ["com.oraclecloud.identitydataplane.LoginUser", "com.oraclecloud.identity.CreateApiKey"],
            "cloud_guard_findings": ["USER_WITHOUT_MFA", "API_KEY_CREATED"],
            "rules": ["OCI Audit | where eventName = 'LoginUser' and additionalDetails.mfaUsed = 'false'"],
            "data_sources": ["OCI Audit Logs", "Identity Activity Logs"],
        },
        "remediation": {
            "immediate": ["Enforce MFA for all IAM users", "Rotate compromised API keys"],
            "preventive": ["Use IDCS federation with MFA", "Implement password policies", "Use Instance Principals instead of API keys"],
            "oci_services": ["OCI IAM", "IDCS", "Cloud Guard", "Instance Principals"],
        },
    },
    "T1098": {
        "detection": {
            "audit_logs": ["com.oraclecloud.identity.AddUserToGroup", "com.oraclecloud.identity.CreatePolicy"],
            "cloud_guard_findings": ["ADMIN_GROUP_MODIFIED", "OVER_PERMISSIVE_POLICY"],
            "rules": ["OCI Audit | where eventName contains 'Policy' or eventName contains 'Group'"],
            "data_sources": ["OCI Audit Logs", "Cloud Guard"],
        },
        "remediation": {
            "immediate": ["Review IAM policy changes in last 24h", "Audit group membership changes"],
            "preventive": ["Use compartment-scoped policies", "Implement tag-based access control", "Cloud Guard detector recipes for IAM changes"],
            "oci_services": ["OCI IAM Policies", "Cloud Guard", "Compartments"],
        },
    },
    "T1485": {
        "detection": {
            "audit_logs": ["com.oraclecloud.objectstorage.DeleteObject", "com.oraclecloud.database.DeleteDbSystem"],
            "cloud_guard_findings": ["MASS_DELETE_OPERATIONS"],
            "rules": ["OCI Audit | where eventName contains 'Delete' | summarize count() by principalId"],
            "data_sources": ["OCI Audit Logs", "Object Storage Logs"],
        },
        "remediation": {
            "immediate": ["Enable Object Storage versioning", "Review Database Backup configurations"],
            "preventive": ["Use Retention Rules on Object Storage buckets", "Enable Database Automatic Backups", "Cloud Guard responder recipes for delete prevention"],
            "oci_services": ["Object Storage Retention Rules", "DB Backups", "Cloud Guard Responders"],
        },
    },
    "T1486": {
        "detection": {
            "audit_logs": ["com.oraclecloud.kms.Encrypt", "com.oraclecloud.kms.CreateKey"],
            "cloud_guard_findings": ["KMS_KEY_ROTATION_DISABLED"],
            "rules": ["OCI Audit | where eventName contains 'kms' and principalId not in (approved_principals)"],
            "data_sources": ["OCI Audit Logs", "KMS Vault Logs"],
        },
        "remediation": {
            "immediate": ["Verify KMS Vault key policies", "Review recent key creation events"],
            "preventive": ["Enable automatic key rotation", "Use OCI Vault with HSM protection", "Compartment-scoped KMS policies"],
            "oci_services": ["OCI Vault", "KMS", "Cloud Guard"],
        },
    },
    "T1530": {
        "detection": {
            "audit_logs": ["com.oraclecloud.objectstorage.GetObject", "com.oraclecloud.objectstorage.ListObjects"],
            "cloud_guard_findings": ["BUCKET_IS_PUBLIC", "BUCKET_NOT_ENCRYPTED"],
            "rules": ["OCI Audit | where eventName = 'GetObject' and sourceAddress not in (known_ips)"],
            "data_sources": ["OCI Audit Logs", "Object Storage Access Logs"],
        },
        "remediation": {
            "immediate": ["Remove public access from buckets", "Enable SSE with customer-managed keys"],
            "preventive": ["Cloud Guard detector for public buckets", "Use Pre-Authenticated Requests with expiry", "Enable Object Storage logging"],
            "oci_services": ["Object Storage", "Cloud Guard", "OCI Vault"],
        },
    },
    "T1562": {
        "detection": {
            "audit_logs": ["com.oraclecloud.audit.UpdateConfiguration", "com.oraclecloud.cloudguard.DisableDetector"],
            "cloud_guard_findings": ["AUDIT_RETENTION_REDUCED"],
            "rules": ["OCI Audit | where eventName contains 'Disable' or eventName contains 'audit'"],
            "data_sources": ["OCI Audit Logs"],
        },
        "remediation": {
            "immediate": ["Verify Audit configuration is enabled (365-day retention)", "Re-enable Cloud Guard detectors"],
            "preventive": ["Use Service Connector Hub to export logs to Object Storage", "Cloud Guard responders for audit changes"],
            "oci_services": ["OCI Audit", "Cloud Guard", "Service Connector Hub", "Logging Analytics"],
        },
    },
    "T1496": {
        "detection": {
            "audit_logs": ["com.oraclecloud.computeapi.LaunchInstance in unusual region"],
            "cloud_guard_findings": ["UNUSUAL_COMPUTE_ACTIVITY"],
            "rules": ["OCI Audit | where eventName = 'LaunchInstance' and compartmentId not in (approved_compartments)"],
            "data_sources": ["OCI Audit Logs", "Monitoring Metrics", "Cost Analysis"],
        },
        "remediation": {
            "immediate": ["Terminate unauthorized compute instances", "Revoke compromised API keys"],
            "preventive": ["Set budgets and alerts", "Compartment quotas for compute shapes", "Cloud Guard detector for unusual compute activity"],
            "oci_services": ["Budgets", "Compartment Quotas", "Cloud Guard"],
        },
    },
    "T1110": {
        "detection": {
            "audit_logs": ["com.oraclecloud.identitydataplane.LoginUser (failures)"],
            "cloud_guard_findings": ["BRUTE_FORCE_DETECTED"],
            "rules": ["OCI Audit | where eventName = 'LoginUser' and outcome = 'failure' | summarize count() by sourceAddress"],
            "data_sources": ["OCI Audit Logs", "IDCS Sign-in Logs"],
        },
        "remediation": {
            "immediate": ["Block source IPs via NSG rules", "Reset affected account passwords"],
            "preventive": ["Enforce MFA for all users", "Password complexity policies", "Use IDCS with adaptive MFA"],
            "oci_services": ["IDCS", "OCI IAM", "Network Security Groups"],
        },
    },
    "T1580": {
        "detection": {
            "audit_logs": ["com.oraclecloud.computeapi.ListInstances", "com.oraclecloud.objectstorage.ListBuckets"],
            "cloud_guard_findings": [],
            "rules": ["OCI Audit | where eventName contains 'List' | summarize dcount(eventName) by principalId | where dcount_ > 15"],
            "data_sources": ["OCI Audit Logs"],
        },
        "remediation": {
            "immediate": ["Review principals performing broad enumeration", "Verify enumeration is authorized"],
            "preventive": ["Use compartment-scoped policies to limit visibility", "Cloud Guard for anomaly detection"],
            "oci_services": ["OCI IAM Policies", "Compartments", "Cloud Guard"],
        },
    },
}


# ── IBM Cloud ────────────────────────────────────────────────────────────────

IBM_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "detection": {
            "activity_tracker_events": ["is.security-group.security-group.create", "is.floating-ip.floating-ip.create"],
            "security_advisor_findings": ["OPEN_SECURITY_GROUP", "PUBLIC_IP_EXPOSURE"],
            "rules": ["Activity Tracker | where action contains 'security-group' and target.publicGateway != null"],
            "data_sources": ["Activity Tracker", "Security Advisor", "VPC Flow Logs"],
        },
        "remediation": {
            "immediate": ["Review Security Groups for unrestricted inbound rules", "Configure IBM Cloud Internet Services WAF"],
            "preventive": ["Use VPC Access Control Lists", "Enable IBM Cloud Internet Services (CIS) WAF", "Use Private Endpoints for services"],
            "ibm_services": ["CIS WAF", "Security Groups", "VPC ACLs", "Security Advisor"],
        },
    },
    "T1078": {
        "detection": {
            "activity_tracker_events": ["iam-identity.user-apikey.login", "iam-identity.serviceid-apikey.login"],
            "security_advisor_findings": ["USER_WITHOUT_MFA", "STALE_API_KEY"],
            "rules": ["Activity Tracker | where action contains 'login' and initiator.credential.type != 'mfa'"],
            "data_sources": ["Activity Tracker", "IAM Activity Logs"],
        },
        "remediation": {
            "immediate": ["Enforce MFA for all IAM users", "Rotate compromised API keys"],
            "preventive": ["Use service IDs with short-lived tokens", "Enable SSO with enterprise IdP", "Set API key rotation policies"],
            "ibm_services": ["IAM", "App ID", "Key Protect"],
        },
    },
    "T1098": {
        "detection": {
            "activity_tracker_events": ["iam-groups.group.create", "iam-access-management.policy.create"],
            "security_advisor_findings": ["OVER_PRIVILEGED_ACCESS"],
            "rules": ["Activity Tracker | where action contains 'policy' or action contains 'group'"],
            "data_sources": ["Activity Tracker", "IAM Audit"],
        },
        "remediation": {
            "immediate": ["Review IAM access policy changes", "Audit access group membership"],
            "preventive": ["Use access groups with least privilege", "Enable IBM Cloud Activity Tracker", "Use trusted profiles instead of API keys"],
            "ibm_services": ["IAM Access Groups", "Activity Tracker", "Trusted Profiles"],
        },
    },
    "T1485": {
        "detection": {
            "activity_tracker_events": ["cloud-object-storage.object.delete", "is.volume.volume.delete"],
            "security_advisor_findings": ["MASS_DELETE_OPERATIONS"],
            "rules": ["Activity Tracker | where action contains 'delete' | summarize count() by initiator.id"],
            "data_sources": ["Activity Tracker", "COS Logs"],
        },
        "remediation": {
            "immediate": ["Enable COS Object Versioning", "Review Block Storage snapshot policies"],
            "preventive": ["Use COS Immutable Object Storage (WORM)", "Enable daily backups for VPC Block Storage", "Object Lock policies"],
            "ibm_services": ["COS Immutable Storage", "VPC Snapshots", "Backup Service"],
        },
    },
    "T1530": {
        "detection": {
            "activity_tracker_events": ["cloud-object-storage.object.read", "cloud-object-storage.bucket.list"],
            "security_advisor_findings": ["PUBLIC_BUCKET", "BUCKET_NOT_ENCRYPTED"],
            "rules": ["Activity Tracker | where action = 'cloud-object-storage.object.read' and source not in (known_ips)"],
            "data_sources": ["Activity Tracker", "COS Access Logs"],
        },
        "remediation": {
            "immediate": ["Remove public access from COS buckets", "Enable SSE-KP encryption"],
            "preventive": ["Use IAM policies to restrict bucket access", "Enable COS Activity Tracker events", "Use Key Protect for envelope encryption"],
            "ibm_services": ["COS", "Key Protect", "IAM", "Activity Tracker"],
        },
    },
    "T1562": {
        "detection": {
            "activity_tracker_events": ["atracker.setting.update", "security-advisor.finding.delete"],
            "security_advisor_findings": ["AUDIT_DISABLED"],
            "rules": ["Activity Tracker | where action contains 'atracker' and requestData contains 'disable'"],
            "data_sources": ["Activity Tracker"],
        },
        "remediation": {
            "immediate": ["Verify Activity Tracker routes are active", "Re-enable Security Advisor findings"],
            "preventive": ["Use COS immutable storage for Activity Tracker logs", "Configure Activity Tracker for all regions"],
            "ibm_services": ["Activity Tracker", "Security Advisor", "COS"],
        },
    },
    "T1496": {
        "detection": {
            "activity_tracker_events": ["is.instance.instance.create in non-standard region"],
            "security_advisor_findings": ["UNUSUAL_COMPUTE_ACTIVITY"],
            "rules": ["Activity Tracker | where action = 'is.instance.instance.create' and target.region not in (approved_regions)"],
            "data_sources": ["Activity Tracker", "Billing", "VPC Metrics"],
        },
        "remediation": {
            "immediate": ["Terminate unauthorized VPC instances", "Revoke compromised credentials"],
            "preventive": ["Set spending notifications and alerts", "Use IAM policies to restrict instance creation by region"],
            "ibm_services": ["Billing", "IAM", "VPC"],
        },
    },
    "T1110": {
        "detection": {
            "activity_tracker_events": ["iam-identity.user-apikey.login (failure)"],
            "security_advisor_findings": ["BRUTE_FORCE_LOGIN"],
            "rules": ["Activity Tracker | where action contains 'login' and outcome = 'failure' | summarize count() by sourceIP"],
            "data_sources": ["Activity Tracker", "IAM Logs"],
        },
        "remediation": {
            "immediate": ["Block source IPs via Security Groups", "Reset compromised passwords"],
            "preventive": ["Enforce MFA", "Use App ID for adaptive access", "Password complexity enforcement"],
            "ibm_services": ["IAM", "App ID", "Security Groups"],
        },
    },
    "T1580": {
        "detection": {
            "activity_tracker_events": ["is.instance.instance.list", "cloud-object-storage.bucket.list"],
            "security_advisor_findings": [],
            "rules": ["Activity Tracker | where action contains '.list' | summarize dcount(action) by initiator.id | where dcount_ > 15"],
            "data_sources": ["Activity Tracker"],
        },
        "remediation": {
            "immediate": ["Review who is performing broad resource enumeration", "Verify service ID permissions"],
            "preventive": ["Use resource groups to limit visibility", "IAM access groups with least privilege"],
            "ibm_services": ["IAM", "Resource Groups", "Activity Tracker"],
        },
    },
    "T1486": {
        "detection": {
            "activity_tracker_events": ["kms.secrets.create", "kms.secrets.wrap"],
            "security_advisor_findings": ["KEY_NOT_ROTATED"],
            "rules": ["Activity Tracker | where action contains 'kms' and initiator.id not in (approved_services)"],
            "data_sources": ["Activity Tracker", "Key Protect Logs"],
        },
        "remediation": {
            "immediate": ["Verify Key Protect key policies", "Review recent key operations"],
            "preventive": ["Enable automatic key rotation", "Use HPCS for highest assurance", "IAM policies restricting key operations"],
            "ibm_services": ["Key Protect", "HPCS", "IAM"],
        },
    },
}


# ── Alicloud ─────────────────────────────────────────────────────────────────

ALICLOUD_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "detection": {
            "actiontrail_events": ["CreateSecurityGroup", "ModifySecurityGroupRule", "AllocateEipAddress"],
            "security_center_alerts": ["OPEN_SECURITY_GROUP", "PUBLIC_EIP_EXPOSED"],
            "rules": ["ActionTrail | where eventName = 'ModifySecurityGroupRule' and requestParameters contains '0.0.0.0/0'"],
            "data_sources": ["ActionTrail", "Security Center", "SLS Logs"],
        },
        "remediation": {
            "immediate": ["Review Security Group rules for 0.0.0.0/0 ingress", "Enable Web Application Firewall"],
            "preventive": ["Use Anti-DDoS with WAF", "Private VSwitch for backend resources", "Cloud Firewall for centralized control"],
            "alicloud_services": ["WAF", "Cloud Firewall", "Anti-DDoS", "Security Center"],
        },
    },
    "T1078": {
        "detection": {
            "actiontrail_events": ["ConsoleSignin", "CreateAccessKey", "AssumeRole"],
            "security_center_alerts": ["COMPROMISED_ACCOUNT", "MFA_NOT_ENABLED"],
            "rules": ["ActionTrail | where eventName = 'ConsoleSignin' and mfaAuthenticated = 'false'"],
            "data_sources": ["ActionTrail", "RAM Logs"],
        },
        "remediation": {
            "immediate": ["Enforce MFA for all RAM users", "Rotate compromised AccessKeys"],
            "preventive": ["Use RAM roles with STS temporary credentials", "SSO with enterprise IdP", "Enable RAM password policy"],
            "alicloud_services": ["RAM", "SSO", "Security Center"],
        },
    },
    "T1098": {
        "detection": {
            "actiontrail_events": ["CreatePolicy", "AttachPolicyToUser", "AddUserToGroup"],
            "security_center_alerts": ["OVER_PRIVILEGED_RAM_USER"],
            "rules": ["ActionTrail | where eventName contains 'Policy' or eventName contains 'Group'"],
            "data_sources": ["ActionTrail", "RAM Audit"],
        },
        "remediation": {
            "immediate": ["Review RAM policy changes", "Audit RAM group membership"],
            "preventive": ["Use custom RAM policies with least privilege", "Enable ActionTrail for all regions"],
            "alicloud_services": ["RAM", "ActionTrail", "Cloud Config"],
        },
    },
    "T1485": {
        "detection": {
            "actiontrail_events": ["DeleteObject", "DeleteBucket", "DeleteDBInstance"],
            "security_center_alerts": ["MASS_DELETE_DETECTED"],
            "rules": ["ActionTrail | where eventName contains 'Delete' | summarize count() by userIdentity.principalId"],
            "data_sources": ["ActionTrail", "OSS Logs"],
        },
        "remediation": {
            "immediate": ["Enable OSS versioning", "Review RDS backup policies"],
            "preventive": ["Use OSS Retention Policy (WORM)", "Enable RDS automatic backups", "Cross-region backup replication"],
            "alicloud_services": ["OSS Versioning", "RDS Backups", "Data Backup Service"],
        },
    },
    "T1530": {
        "detection": {
            "actiontrail_events": ["GetObject", "GetBucketAcl"],
            "security_center_alerts": ["PUBLIC_OSS_BUCKET", "OSS_NOT_ENCRYPTED"],
            "rules": ["ActionTrail | where eventName = 'GetObject' and sourceIP not in (known_ips)"],
            "data_sources": ["ActionTrail", "OSS Access Logs"],
        },
        "remediation": {
            "immediate": ["Remove public-read/public-read-write from OSS buckets", "Enable server-side encryption"],
            "preventive": ["Use RAM policies to restrict OSS access", "Enable OSS logging", "Use VPC endpoints for OSS"],
            "alicloud_services": ["OSS", "RAM", "KMS", "VPC Endpoints"],
        },
    },
    "T1562": {
        "detection": {
            "actiontrail_events": ["StopActionTrail", "DeleteTrail"],
            "security_center_alerts": ["AUDIT_DISABLED"],
            "rules": ["ActionTrail | where eventName contains 'Trail' and eventName contains 'Stop' or 'Delete'"],
            "data_sources": ["ActionTrail"],
        },
        "remediation": {
            "immediate": ["Re-enable ActionTrail", "Verify SLS log retention"],
            "preventive": ["Export ActionTrail to OSS with WORM", "Enable Security Center threat detection"],
            "alicloud_services": ["ActionTrail", "SLS", "Security Center"],
        },
    },
    "T1496": {
        "detection": {
            "actiontrail_events": ["RunInstances in unusual region"],
            "security_center_alerts": ["CRYPTOMINING_THREAT"],
            "rules": ["ActionTrail | where eventName = 'RunInstances' and regionId not in (approved_regions)"],
            "data_sources": ["ActionTrail", "BSS Billing", "Security Center"],
        },
        "remediation": {
            "immediate": ["Terminate unauthorized ECS instances", "Revoke compromised AccessKeys"],
            "preventive": ["Set billing alerts and budgets", "Use Cloud Config to restrict regions"],
            "alicloud_services": ["BSS", "Cloud Config", "Security Center"],
        },
    },
    "T1110": {
        "detection": {
            "actiontrail_events": ["ConsoleSignin (failure)"],
            "security_center_alerts": ["BRUTE_FORCE_ATTACK"],
            "rules": ["ActionTrail | where eventName = 'ConsoleSignin' and errorCode = 'AuthenticationFailed'"],
            "data_sources": ["ActionTrail", "RAM Logs"],
        },
        "remediation": {
            "immediate": ["Block source IPs via Security Group", "Reset affected passwords"],
            "preventive": ["Enforce MFA", "RAM password complexity policies", "Enable Security Center brute force detection"],
            "alicloud_services": ["RAM", "Security Center", "Security Groups"],
        },
    },
    "T1580": {
        "detection": {
            "actiontrail_events": ["DescribeInstances", "ListBuckets", "DescribeSecurityGroups"],
            "security_center_alerts": [],
            "rules": ["ActionTrail | where eventName contains 'Describe' or eventName contains 'List' | summarize dcount(eventName) by userIdentity"],
            "data_sources": ["ActionTrail"],
        },
        "remediation": {
            "immediate": ["Review principals performing broad enumeration", "Verify legitimate need"],
            "preventive": ["Use RAM policies to scope resource access", "Resource group segmentation"],
            "alicloud_services": ["RAM", "Resource Groups", "ActionTrail"],
        },
    },
    "T1486": {
        "detection": {
            "actiontrail_events": ["CreateKey", "Encrypt"],
            "security_center_alerts": ["KMS_KEY_ROTATION_DISABLED"],
            "rules": ["ActionTrail | where eventName contains 'kms' and userIdentity not in (approved_services)"],
            "data_sources": ["ActionTrail", "KMS Logs"],
        },
        "remediation": {
            "immediate": ["Verify KMS key policies", "Review recent key operations"],
            "preventive": ["Enable automatic key rotation", "Use HSM-backed keys", "Restrict KMS permissions"],
            "alicloud_services": ["KMS", "RAM", "Security Center"],
        },
    },
}


# ── Kubernetes ───────────────────────────────────────────────────────────────

K8S_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "detection": {
            "audit_logs": ["create Service type=LoadBalancer", "create Ingress"],
            "falco_alerts": ["Unexpected inbound connection", "Service exposed to internet"],
            "rules": ["K8s Audit | where verb = 'create' and resource = 'services' and spec.type = 'LoadBalancer'"],
            "data_sources": ["K8s Audit Logs", "Falco", "Network Policies"],
        },
        "remediation": {
            "immediate": ["Review Services of type LoadBalancer", "Audit Ingress resources for public exposure"],
            "preventive": ["Use NetworkPolicies to restrict pod ingress", "Use internal LoadBalancers", "Deploy Ingress controllers with WAF"],
            "k8s_services": ["NetworkPolicies", "Ingress Controllers", "Service Mesh"],
        },
    },
    "T1078": {
        "detection": {
            "audit_logs": ["create ServiceAccount", "create ClusterRoleBinding", "tokenRequest"],
            "falco_alerts": ["ServiceAccount token used from unusual source"],
            "rules": ["K8s Audit | where verb = 'create' and resource = 'serviceaccounts'"],
            "data_sources": ["K8s Audit Logs", "OIDC Provider Logs"],
        },
        "remediation": {
            "immediate": ["Review ServiceAccount token usage", "Audit ClusterRoleBindings for cluster-admin"],
            "preventive": ["Use OIDC/IRSA instead of static SA tokens", "Disable automountServiceAccountToken", "Use short-lived tokens (TokenRequest API)"],
            "k8s_services": ["RBAC", "OIDC", "Pod Security Admission"],
        },
    },
    "T1098": {
        "detection": {
            "audit_logs": ["create ClusterRole", "create RoleBinding", "patch ClusterRoleBinding"],
            "falco_alerts": ["ClusterRole modified", "New cluster-admin binding"],
            "rules": ["K8s Audit | where verb in ('create','patch') and resource in ('clusterroles','clusterrolebindings')"],
            "data_sources": ["K8s Audit Logs"],
        },
        "remediation": {
            "immediate": ["Review ClusterRoleBindings for cluster-admin", "Audit recent RBAC changes"],
            "preventive": ["Use namespace-scoped Roles instead of ClusterRoles", "OPA Gatekeeper to restrict RBAC changes", "Least-privilege RBAC policies"],
            "k8s_services": ["RBAC", "OPA Gatekeeper", "Kyverno"],
        },
    },
    "T1485": {
        "detection": {
            "audit_logs": ["delete PersistentVolumeClaim", "delete Namespace", "delete StatefulSet"],
            "falco_alerts": ["Mass deletion of resources"],
            "rules": ["K8s Audit | where verb = 'delete' | summarize count() by user.username | where count_ > 10"],
            "data_sources": ["K8s Audit Logs", "etcd Metrics"],
        },
        "remediation": {
            "immediate": ["Review recent delete operations", "Verify PV reclaim policies are set to Retain"],
            "preventive": ["Set PersistentVolume reclaimPolicy=Retain", "Use VolumeSnapshot for backups", "OPA policies to block mass deletions"],
            "k8s_services": ["VolumeSnapshots", "etcd Backups", "OPA Gatekeeper"],
        },
    },
    "T1525": {
        "detection": {
            "audit_logs": ["create Pod with image from unknown registry"],
            "falco_alerts": ["Container started with untrusted image", "Binary executed in container not in image"],
            "rules": ["K8s Audit | where verb = 'create' and resource = 'pods' and spec.image not contains (approved_registry)"],
            "data_sources": ["K8s Audit Logs", "Falco", "Image Registry Logs"],
        },
        "remediation": {
            "immediate": ["Scan running container images for vulnerabilities", "Review recently deployed images"],
            "preventive": ["Use admission controllers for image verification", "OPA Gatekeeper/Kyverno image allowlists", "Enable image signing (cosign/Notary)"],
            "k8s_services": ["Admission Controllers", "OPA Gatekeeper", "Cosign/Notary", "Trivy"],
        },
    },
    "T1562": {
        "detection": {
            "audit_logs": ["delete AuditPolicy", "patch AuditSink", "delete Falco DaemonSet"],
            "falco_alerts": ["Audit policy modified", "Falco process terminated"],
            "rules": ["K8s Audit | where resource in ('auditsinks','daemonsets') and verb in ('delete','patch')"],
            "data_sources": ["K8s Audit Logs", "Node Logs"],
        },
        "remediation": {
            "immediate": ["Verify audit policy is active", "Check Falco DaemonSet is running on all nodes"],
            "preventive": ["Use immutable audit policies", "Export audit logs to external SIEM", "Monitor DaemonSet health with alerts"],
            "k8s_services": ["Audit Policies", "Falco", "Prometheus Alertmanager"],
        },
    },
    "T1496": {
        "detection": {
            "audit_logs": ["create Pod/Deployment with high resource requests"],
            "falco_alerts": ["Crypto miner process detected", "Unexpected outbound connection to mining pool"],
            "rules": ["K8s Audit | where verb = 'create' and spec.resources.requests.cpu > '4'"],
            "data_sources": ["K8s Audit Logs", "Falco", "cAdvisor Metrics"],
        },
        "remediation": {
            "immediate": ["Kill pods with crypto mining processes", "Review images for embedded miners"],
            "preventive": ["Set ResourceQuotas per namespace", "LimitRanges for CPU/memory", "Pod Security Admission to block privileged containers"],
            "k8s_services": ["ResourceQuotas", "LimitRanges", "Pod Security Admission", "Falco"],
        },
    },
    "T1530": {
        "detection": {
            "audit_logs": ["get Secret", "list Secrets"],
            "falco_alerts": ["Secret accessed by unauthorized ServiceAccount"],
            "rules": ["K8s Audit | where verb in ('get','list') and resource = 'secrets' | summarize count() by user.username"],
            "data_sources": ["K8s Audit Logs"],
        },
        "remediation": {
            "immediate": ["Audit Secret access patterns", "Review RBAC for Secret permissions"],
            "preventive": ["Use external secrets managers (Vault, AWS Secrets Manager)", "Enable Secret encryption at rest", "Namespace-scoped Secret access only"],
            "k8s_services": ["Sealed Secrets", "External Secrets Operator", "Vault", "RBAC"],
        },
    },
    "T1059": {
        "detection": {
            "audit_logs": ["exec into Pod", "create Pod with command override"],
            "falco_alerts": ["Shell spawned in container", "Unexpected process in container"],
            "rules": ["K8s Audit | where verb = 'create' and subresource = 'exec'"],
            "data_sources": ["K8s Audit Logs", "Falco Runtime Monitoring"],
        },
        "remediation": {
            "immediate": ["Review exec sessions into pods", "Check for unauthorized shell access"],
            "preventive": ["Disable exec access via RBAC", "Use read-only root filesystems", "Pod Security Admission to block privileged exec"],
            "k8s_services": ["RBAC", "Pod Security Admission", "Falco", "Read-only Filesystem"],
        },
    },
    "T1580": {
        "detection": {
            "audit_logs": ["list Pods across namespaces", "list Nodes", "list Namespaces"],
            "falco_alerts": ["Broad API enumeration from Pod"],
            "rules": ["K8s Audit | where verb = 'list' | summarize dcount(resource) by user.username | where dcount_ > 10"],
            "data_sources": ["K8s Audit Logs"],
        },
        "remediation": {
            "immediate": ["Review ServiceAccounts performing broad enumeration", "Check for compromised tokens"],
            "preventive": ["Namespace-scoped RBAC only", "Disable cluster-wide list permissions", "Use Network Policies to limit API access"],
            "k8s_services": ["RBAC", "NetworkPolicies", "Falco"],
        },
    },
}


# ── Consolidation ────────────────────────────────────────────────────────────

ALL_CSP_GUIDANCE = {
    "oci": OCI_GUIDANCE,
    "ibm": IBM_GUIDANCE,
    "alicloud": ALICLOUD_GUIDANCE,
    "k8s": K8S_GUIDANCE,
}


def update_guidance(conn, csp_filter: str = None, dry_run: bool = False):
    """Merge CSP-specific guidance into mitre_technique_reference JSONB."""
    updated = 0
    skipped = 0

    csps_to_process = {csp_filter: ALL_CSP_GUIDANCE[csp_filter]} if csp_filter else ALL_CSP_GUIDANCE

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for csp_name, csp_data in csps_to_process.items():
            print(f"\n  ── {csp_name.upper()} ({len(csp_data)} techniques) ──")

            for tech_id, data in csp_data.items():
                cur.execute("""
                    SELECT technique_id, detection_guidance, remediation_guidance
                    FROM mitre_technique_reference
                    WHERE technique_id = %s
                """, (tech_id,))
                row = cur.fetchone()

                if not row:
                    print(f"    SKIP (not in DB): {tech_id}")
                    skipped += 1
                    continue

                # Merge detection_guidance
                det = row["detection_guidance"] or {}
                if csp_name not in det and "detection" in data:
                    det[csp_name] = data["detection"]

                # Merge remediation_guidance
                rem = row["remediation_guidance"] or {}
                if csp_name not in rem and "remediation" in data:
                    rem[csp_name] = data["remediation"]

                if dry_run:
                    orig_det = row["detection_guidance"] or {}
                    already = csp_name in orig_det
                    print(f"    {'SKIP (already has {})'.format(csp_name) if already else 'WOULD ADD'}: {tech_id}")
                else:
                    cur.execute("""
                        UPDATE mitre_technique_reference
                        SET detection_guidance = %s,
                            remediation_guidance = %s,
                            updated_at = NOW()
                        WHERE technique_id = %s
                    """, (Json(det), Json(rem), tech_id))
                    print(f"    UPDATED: {tech_id}")

                updated += 1

    if not dry_run:
        conn.commit()

    return updated, skipped


def verify_coverage(conn):
    """Show CSP coverage in guidance JSONB."""
    csps = ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        print("\n  CSP Coverage in detection_guidance:")
        for csp in csps:
            if csp == "aws":
                # AWS uses top-level keys, not a nested section
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM mitre_technique_reference
                    WHERE detection_guidance ? 'cloudtrail_events'
                """)
            else:
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM mitre_technique_reference
                    WHERE detection_guidance ? %s
                """, (csp,))
            row = cur.fetchone()
            print(f"    {csp:10s} {row['cnt']:3d} techniques")


def main():
    parser = argparse.ArgumentParser(description="Extend MITRE guidance with OCI/IBM/Alicloud/K8s")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument("--csp", choices=["oci", "ibm", "alicloud", "k8s"],
                        help="Only process a single CSP (default: all)")
    args = parser.parse_args()

    conn = get_conn()

    total_techs = sum(len(v) for v in ALL_CSP_GUIDANCE.values())
    if args.csp:
        total_techs = len(ALL_CSP_GUIDANCE[args.csp])

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Extending MITRE guidance: "
          f"{args.csp.upper() if args.csp else 'OCI + IBM + Alicloud + K8s'}")
    print(f"Total technique-CSP pairs: {total_techs}")
    print(f"{'='*70}")

    updated, skipped = update_guidance(conn, args.csp, args.dry_run)

    print(f"\n{'='*70}")
    action = "Would update" if args.dry_run else "Updated"
    print(f"{action}: {updated} | Skipped: {skipped}")

    if not args.dry_run:
        verify_coverage(conn)

    print(f"{'='*70}\n")

    conn.close()


if __name__ == "__main__":
    main()
