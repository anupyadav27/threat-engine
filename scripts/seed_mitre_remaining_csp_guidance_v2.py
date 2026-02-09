#!/usr/bin/env python3
"""
Expand MITRE Technique Guidance for OCI, IBM, Alicloud, K8s — V2 (Gap Fill).

The v1 script (seed_mitre_remaining_csp_guidance.py) added 10 core techniques.
This v2 adds the REMAINING 28 techniques so all 4 CSPs match Azure/GCP coverage (38).

Usage:
    python scripts/seed_mitre_remaining_csp_guidance_v2.py --dry-run
    python scripts/seed_mitre_remaining_csp_guidance_v2.py
    python scripts/seed_mitre_remaining_csp_guidance_v2.py --csp oci
"""

import argparse
import json
import os
import sys

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


# ── OCI Guidance for 28 gap techniques ──────────────────────────────────
OCI_GUIDANCE = {
    "T1040": {
        "det": {"audit_logs": ["GetVnicAttachment", "ListVnics", "UpdateVnic"], "cloud_guard_findings": ["Network packet capture detected", "Unusual VCN traffic monitoring"], "data_sources": ["OCI Audit", "VCN Flow Logs"]},
        "rem": {"immediate": ["Review VCN flow log destinations", "Check for unauthorized network captures"], "preventive": ["Enable VCN flow logs", "Restrict NSG rules", "Use private subnets"], "oci_services": ["VCN Flow Logs", "Cloud Guard", "Network Security Groups"]},
    },
    "T1046": {
        "det": {"audit_logs": ["ListInstances", "ListVnics", "GetSubnet"], "cloud_guard_findings": ["Port scanning detected", "Network reconnaissance activity"], "data_sources": ["OCI Audit", "VCN Flow Logs", "Cloud Guard"]},
        "rem": {"immediate": ["Block scanning source IPs via NSG", "Review security list rules"], "preventive": ["Minimize open ports in security lists", "Use network security groups", "Enable Cloud Guard network detector"], "oci_services": ["Network Security Groups", "Cloud Guard", "VCN Flow Logs"]},
    },
    "T1048": {
        "det": {"audit_logs": ["CreateBucketReplication", "UpdateBucket", "GetObject"], "cloud_guard_findings": ["Unusual data transfer pattern", "Large outbound data transfer"], "data_sources": ["OCI Audit", "Object Storage Logs", "VCN Flow Logs"]},
        "rem": {"immediate": ["Block unauthorized egress via NSG", "Review bucket replication rules"], "preventive": ["Restrict outbound NSG rules", "Monitor data transfer volumes", "Use private endpoints for object storage"], "oci_services": ["Object Storage", "VCN Flow Logs", "Cloud Guard"]},
    },
    "T1049": {
        "det": {"audit_logs": ["ListVnicAttachments", "ListNetworkSecurityGroups", "GetVcn"], "cloud_guard_findings": ["Network enumeration detected"], "data_sources": ["OCI Audit", "VCN Flow Logs"]},
        "rem": {"immediate": ["Review IAM policies for network discovery permissions", "Check for unauthorized API access"], "preventive": ["Apply least-privilege network IAM", "Enable Cloud Guard activity detector"], "oci_services": ["IAM", "Cloud Guard", "VCN"]},
    },
    "T1059": {
        "det": {"audit_logs": ["RunCommand", "CreateInstanceConsoleConnection", "LaunchInstance"], "cloud_guard_findings": ["Suspicious command execution on instance", "Console connection to sensitive instance"], "data_sources": ["OCI Audit", "OS Management Agent Logs"]},
        "rem": {"immediate": ["Terminate suspicious console connections", "Review instance run commands"], "preventive": ["Restrict RunCommand IAM policies", "Use bastion service instead of console connections"], "oci_services": ["OS Management", "Bastion", "Cloud Guard"]},
    },
    "T1069": {
        "det": {"audit_logs": ["ListGroups", "ListDynamicGroups", "ListPolicies", "GetGroup"], "cloud_guard_findings": ["IAM enumeration detected", "Bulk group listing"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Review who is performing group enumeration", "Check for compromised users"], "preventive": ["Restrict ListGroups permissions", "Enable Cloud Guard IAM detector"], "oci_services": ["IAM", "Cloud Guard", "Audit"]},
    },
    "T1087": {
        "det": {"audit_logs": ["ListUsers", "ListApiKeys", "ListAuthTokens", "GetUser"], "cloud_guard_findings": ["User account enumeration detected", "Bulk API key listing"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Investigate bulk user enumeration", "Check for compromised credentials"], "preventive": ["Restrict user listing permissions", "Use dynamic groups instead of user-based access"], "oci_services": ["IAM", "Cloud Guard", "Audit"]},
    },
    "T1119": {
        "det": {"audit_logs": ["GetObject", "ListObjects", "BulkDownload"], "cloud_guard_findings": ["Automated data collection from Object Storage", "Bulk object access pattern"], "data_sources": ["OCI Audit", "Object Storage Logs"]},
        "rem": {"immediate": ["Review bulk access patterns", "Rotate affected credentials"], "preventive": ["Enable Object Storage access logging", "Apply retention policies", "Use pre-authenticated requests with expiration"], "oci_services": ["Object Storage", "Cloud Guard", "IAM"]},
    },
    "T1136": {
        "det": {"audit_logs": ["CreateUser", "CreateGroup", "CreateDynamicGroup", "CreatePolicy"], "cloud_guard_findings": ["Unauthorized user creation", "New IAM user with broad permissions"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Delete unauthorized users/groups", "Review associated policies"], "preventive": ["Use dynamic groups and instance principals", "Alert on CreateUser events", "Enforce tagging on new resources"], "oci_services": ["IAM", "Cloud Guard", "Events Service"]},
    },
    "T1199": {
        "det": {"audit_logs": ["CreateCrossConnectGroup", "UpdateIdentityProvider", "CreatePolicy"], "cloud_guard_findings": ["New cross-tenancy policy created", "Federation provider modified"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Audit cross-tenancy policies", "Review identity federation configs"], "preventive": ["Minimize cross-tenancy access", "Use compartment-level isolation", "Review federation providers regularly"], "oci_services": ["IAM Federation", "Cloud Guard", "Compartments"]},
    },
    "T1201": {
        "det": {"audit_logs": ["GetAuthenticationPolicy", "ListPasswordPolicies"], "cloud_guard_findings": ["Password policy enumeration detected"], "data_sources": ["OCI Audit"]},
        "rem": {"immediate": ["Check who queried password policies", "Verify authentication policies unchanged"], "preventive": ["Enforce strong authentication policies", "Enable MFA for all users"], "oci_services": ["IAM", "Cloud Guard"]},
    },
    "T1204": {
        "det": {"audit_logs": ["LaunchInstance", "CreateFunction", "InvokeFunction"], "cloud_guard_findings": ["Suspicious instance launch", "Unauthorized function invocation"], "data_sources": ["OCI Audit", "Functions Logs"]},
        "rem": {"immediate": ["Terminate suspicious instances/functions", "Review launch configurations"], "preventive": ["Restrict instance launch to approved images", "Use image signing", "Compartment-level access control"], "oci_services": ["Compute", "Functions", "Cloud Guard"]},
    },
    "T1490": {
        "det": {"audit_logs": ["DeleteBackup", "DeleteBootVolumeBackup", "DeleteDbBackup", "TerminateAutonomousDatabase"], "cloud_guard_findings": ["Backup deletion detected", "Recovery inhibition activity"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Restore from remaining backups", "Block the deleting principal"], "preventive": ["Enable backup retention locks", "Use cross-region backup replication", "Restrict DeleteBackup permissions"], "oci_services": ["Block Volumes", "Database Backups", "Cloud Guard"]},
    },
    "T1491": {
        "det": {"audit_logs": ["UpdateLoadBalancer", "UpdateWafPolicy", "PutObject"], "cloud_guard_findings": ["Web application defacement attempt", "Unauthorized content modification"], "data_sources": ["OCI Audit", "WAF Logs", "Object Storage Logs"]},
        "rem": {"immediate": ["Revert modified content from backups", "Block attacker access"], "preventive": ["Enable WAF protection", "Use versioning on Object Storage", "Content integrity monitoring"], "oci_services": ["WAF", "Object Storage", "Cloud Guard"]},
    },
    "T1498": {
        "det": {"audit_logs": ["UpdateNetworkSecurityGroup", "UpdateSecurityList"], "cloud_guard_findings": ["DDoS pattern detected", "Volumetric network attack"], "data_sources": ["VCN Flow Logs", "Cloud Guard", "WAF Logs"]},
        "rem": {"immediate": ["Enable DDoS protection", "Block attack source CIDRs"], "preventive": ["Use WAF with rate limiting", "Deploy load balancers with DDoS protection", "Configure NSG rate limits"], "oci_services": ["WAF", "Load Balancer", "Cloud Guard"]},
    },
    "T1499": {
        "det": {"audit_logs": ["UpdateLoadBalancer", "GetLoadBalancerHealth"], "cloud_guard_findings": ["Application-layer DoS detected", "Service degradation"], "data_sources": ["WAF Logs", "Load Balancer Logs", "Cloud Guard"]},
        "rem": {"immediate": ["Scale compute resources", "Enable WAF bot management"], "preventive": ["Configure WAF rate limiting", "Use autoscaling groups", "Deploy CDN for static content"], "oci_services": ["WAF", "Load Balancer", "Autoscaling", "CDN"]},
    },
    "T1525": {
        "det": {"audit_logs": ["CreateContainerImage", "PushImage", "UpdateContainerRepository"], "cloud_guard_findings": ["Unscanned container image deployed", "Image with vulnerabilities pushed"], "data_sources": ["OCI Audit", "Container Registry Logs"]},
        "rem": {"immediate": ["Remove compromised images", "Redeploy from trusted base images"], "preventive": ["Enable image scanning in Container Registry", "Use signed images only", "Enforce image pull policies"], "oci_services": ["Container Registry", "Container Instances", "Cloud Guard"]},
    },
    "T1526": {
        "det": {"audit_logs": ["ListCompartments", "ListInstances", "ListBuckets", "ListAutonomousDatabases"], "cloud_guard_findings": ["Cloud service enumeration detected", "Bulk resource listing"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Investigate enumeration source", "Check for compromised credentials"], "preventive": ["Compartment-level IAM", "Restrict List* permissions", "Enable Cloud Guard activity detector"], "oci_services": ["IAM", "Compartments", "Cloud Guard"]},
    },
    "T1531": {
        "det": {"audit_logs": ["DeleteUser", "RemoveUserFromGroup", "DeleteApiKey", "DeleteAuthToken"], "cloud_guard_findings": ["Account access removal detected", "Critical IAM change"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Restore deleted users/keys", "Re-grant removed group memberships"], "preventive": ["Restrict DeleteUser/RemoveUserFromGroup permissions", "Alert on IAM destructive actions", "Use break-glass procedures"], "oci_services": ["IAM", "Events Service", "Cloud Guard"]},
    },
    "T1535": {
        "det": {"audit_logs": ["CreateInstance", "CreateBucket", "CreateAutonomousDatabase"], "cloud_guard_findings": ["Resource created in unused region", "Activity in non-standard region"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Terminate resources in unauthorized regions", "Investigate creating principal"], "preventive": ["Restrict tenancy to approved regions only", "Alert on resource creation in non-standard regions"], "oci_services": ["IAM Region Subscription", "Cloud Guard", "Events Service"]},
    },
    "T1537": {
        "det": {"audit_logs": ["CreateBucketReplication", "CreateCrossConnectGroup", "UpdateBucket"], "cloud_guard_findings": ["Cross-tenancy data transfer detected", "Bucket replication to external destination"], "data_sources": ["OCI Audit", "Object Storage Logs"]},
        "rem": {"immediate": ["Remove unauthorized replication rules", "Block external tenancy access"], "preventive": ["Restrict cross-tenancy policies", "Monitor data transfer destinations", "Use private endpoints"], "oci_services": ["Object Storage", "IAM", "Cloud Guard"]},
    },
    "T1538": {
        "det": {"audit_logs": ["GetConsoleHistory", "ListWorkRequests", "GetTenancy"], "cloud_guard_findings": ["Console dashboard enumeration detected"], "data_sources": ["OCI Audit"]},
        "rem": {"immediate": ["Review console access logs", "Check for unauthorized sessions"], "preventive": ["Enforce MFA for console access", "Restrict tenancy-level read permissions"], "oci_services": ["IAM", "Console", "Cloud Guard"]},
    },
    "T1550": {
        "det": {"audit_logs": ["CreateAuthToken", "GenerateSessionToken", "UploadApiKey"], "cloud_guard_findings": ["Token reuse from unusual location", "Alternate credential material detected"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Revoke suspicious tokens", "Rotate API keys"], "preventive": ["Use short-lived tokens", "Enforce IP-based restrictions on auth tokens", "Enable MFA"], "oci_services": ["IAM", "Cloud Guard", "Audit"]},
    },
    "T1552.005": {
        "det": {"audit_logs": ["GetInstanceMetadata", "ListInstanceMetadata"], "cloud_guard_findings": ["Instance metadata API abuse", "SSRF targeting metadata endpoint"], "data_sources": ["OCI Audit", "Instance Logs"]},
        "rem": {"immediate": ["Rotate instance principal credentials", "Block metadata access from containers"], "preventive": ["Use instance principals instead of user credentials", "Restrict metadata service access", "Use IMDSv2-equivalent controls"], "oci_services": ["Compute", "IAM Instance Principals", "Cloud Guard"]},
    },
    "T1556": {
        "det": {"audit_logs": ["UpdateIdentityProvider", "UpdateAuthenticationPolicy", "CreateIdentityProvider"], "cloud_guard_findings": ["Authentication flow modified", "Identity provider configuration changed"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Revert authentication policy changes", "Review identity provider configs"], "preventive": ["Alert on auth policy changes", "Restrict UpdateIdentityProvider permissions", "Regular federation audits"], "oci_services": ["IAM Federation", "Cloud Guard", "Events Service"]},
    },
    "T1562.008": {
        "det": {"audit_logs": ["UpdateConfiguration", "DeleteLogGroup", "DeleteUnifiedAgentConfiguration"], "cloud_guard_findings": ["Logging disabled", "Audit configuration modified"], "data_sources": ["OCI Audit", "Logging Service"]},
        "rem": {"immediate": ["Re-enable disabled logging", "Restore deleted log groups"], "preventive": ["Restrict logging deletion permissions", "Use service connector to archive logs externally", "Alert on logging config changes"], "oci_services": ["Logging", "Cloud Guard", "Events Service"]},
    },
    "T1578": {
        "det": {"audit_logs": ["UpdateInstance", "CreateImage", "LaunchInstance", "TerminateInstance"], "cloud_guard_findings": ["Compute infrastructure modification", "Unauthorized instance cloning"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Revert unauthorized compute changes", "Terminate cloned instances"], "preventive": ["Restrict compute modification permissions", "Use tag-based access policies", "Enable Cloud Guard compute detector"], "oci_services": ["Compute", "IAM", "Cloud Guard"]},
    },
    "T1606": {
        "det": {"audit_logs": ["CreateAuthToken", "UpdateIdentityProvider", "CreateOAuthClient"], "cloud_guard_findings": ["Suspicious credential forging", "OAuth token anomaly"], "data_sources": ["OCI Audit", "Cloud Guard"]},
        "rem": {"immediate": ["Revoke forged credentials", "Reset affected identity providers"], "preventive": ["Use short-lived tokens", "Monitor token issuance patterns", "Enforce strict OIDC validation"], "oci_services": ["IAM", "Cloud Guard", "Identity Domains"]},
    },
}

# ── IBM Guidance for 28 gap techniques ──────────────────────────────────
IBM_GUIDANCE = {
    "T1040": {
        "det": {"activity_tracker_events": ["is.flow-log-collector.flow-log-collector.create", "is.vpc.virtual-network-interface.update"], "security_advisor_findings": ["Network packet capture detected", "Unusual VPC traffic monitoring"], "data_sources": ["Activity Tracker", "VPC Flow Logs"]},
        "rem": {"immediate": ["Review flow log destinations", "Check for unauthorized packet captures"], "preventive": ["Enable VPC flow logs", "Restrict security group rules", "Use private subnets"], "ibm_services": ["VPC Flow Logs", "Security Advisor", "Security Groups"]},
    },
    "T1046": {
        "det": {"activity_tracker_events": ["is.instance.instance.list", "is.subnet.subnet.list", "is.security-group.security-group.list"], "security_advisor_findings": ["Port scanning detected", "Network reconnaissance"], "data_sources": ["Activity Tracker", "VPC Flow Logs"]},
        "rem": {"immediate": ["Block scanning IPs via security groups", "Review inbound rules"], "preventive": ["Minimize open ports", "Use network ACLs", "Enable Security Advisor network insights"], "ibm_services": ["Security Groups", "Network ACLs", "Security Advisor"]},
    },
    "T1048": {
        "det": {"activity_tracker_events": ["cloud-object-storage.bucket.create_replication", "cloud-object-storage.object.get"], "security_advisor_findings": ["Unusual data transfer pattern", "Large outbound data movement"], "data_sources": ["Activity Tracker", "COS Activity Logs"]},
        "rem": {"immediate": ["Block unauthorized egress", "Review COS replication rules"], "preventive": ["Restrict outbound security group rules", "Monitor data transfer volumes", "Use private endpoints for COS"], "ibm_services": ["Cloud Object Storage", "VPC Flow Logs", "Security Advisor"]},
    },
    "T1049": {
        "det": {"activity_tracker_events": ["is.vpc.vpc.read", "is.network-acl.network-acl.list", "is.security-group.security-group.list"], "security_advisor_findings": ["Network connection enumeration detected"], "data_sources": ["Activity Tracker", "VPC Flow Logs"]},
        "rem": {"immediate": ["Review IAM for network read permissions", "Check for unauthorized API access"], "preventive": ["Apply least-privilege for network IAM", "Enable Security Advisor"], "ibm_services": ["IAM", "Security Advisor", "VPC"]},
    },
    "T1059": {
        "det": {"activity_tracker_events": ["is.instance.instance.action", "code-engine.application.create", "cloud-functions.action.invoke"], "security_advisor_findings": ["Suspicious command execution", "Unauthorized function invocation"], "data_sources": ["Activity Tracker", "Cloud Functions Logs"]},
        "rem": {"immediate": ["Terminate suspicious actions", "Review function invocations"], "preventive": ["Restrict RunCommand permissions", "Use Code Engine with trusted images only"], "ibm_services": ["Code Engine", "Cloud Functions", "Security Advisor"]},
    },
    "T1069": {
        "det": {"activity_tracker_events": ["iam-identity.access-group.list", "iam-identity.access-group.read", "iam-identity.trusted-profile.list"], "security_advisor_findings": ["IAM group enumeration detected", "Bulk access group listing"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Investigate group enumeration source", "Check for compromised keys"], "preventive": ["Restrict access group listing permissions", "Enable Security Advisor IAM insights"], "ibm_services": ["IAM", "Security Advisor", "Activity Tracker"]},
    },
    "T1087": {
        "det": {"activity_tracker_events": ["iam-identity.user.list", "iam-identity.apikey.list", "iam-identity.serviceid.list"], "security_advisor_findings": ["User account enumeration detected", "Bulk API key listing"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Investigate bulk user listing", "Rotate potentially compromised API keys"], "preventive": ["Restrict user listing permissions", "Use service IDs with trusted profiles"], "ibm_services": ["IAM", "Security Advisor", "Activity Tracker"]},
    },
    "T1119": {
        "det": {"activity_tracker_events": ["cloud-object-storage.object.get", "cloud-object-storage.bucket.list_objects"], "security_advisor_findings": ["Automated data collection pattern", "Bulk object access"], "data_sources": ["Activity Tracker", "COS Activity Logs"]},
        "rem": {"immediate": ["Review bulk access patterns", "Rotate affected credentials"], "preventive": ["Enable COS access logging", "Apply object retention policies", "Use HMAC key rotation"], "ibm_services": ["Cloud Object Storage", "Security Advisor", "IAM"]},
    },
    "T1136": {
        "det": {"activity_tracker_events": ["iam-identity.user.create", "iam-identity.serviceid.create", "iam-identity.trusted-profile.create"], "security_advisor_findings": ["Unauthorized user creation", "New service ID with broad permissions"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Delete unauthorized users/service IDs", "Review associated IAM policies"], "preventive": ["Use trusted profiles instead of user accounts", "Alert on user creation events", "Enforce resource tagging"], "ibm_services": ["IAM", "Security Advisor", "Event Notifications"]},
    },
    "T1199": {
        "det": {"activity_tracker_events": ["iam-identity.trusted-profile.create", "transit.gateway.connection.create", "direct-link.gateway.create"], "security_advisor_findings": ["New cross-account trusted profile", "Transit gateway connection to unknown account"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Audit trusted profiles", "Review transit gateway connections"], "preventive": ["Minimize cross-account trust", "Use enterprise account boundaries", "Review trusted profiles regularly"], "ibm_services": ["IAM Trusted Profiles", "Transit Gateway", "Security Advisor"]},
    },
    "T1201": {
        "det": {"activity_tracker_events": ["iam-identity.account-settings.read"], "security_advisor_findings": ["Password policy enumeration detected"], "data_sources": ["Activity Tracker"]},
        "rem": {"immediate": ["Check who queried account settings", "Verify settings unchanged"], "preventive": ["Enforce strong password policy", "Enable MFA for all users"], "ibm_services": ["IAM", "Security Advisor"]},
    },
    "T1204": {
        "det": {"activity_tracker_events": ["is.instance.instance.create", "code-engine.application.create", "cloud-functions.action.create"], "security_advisor_findings": ["Suspicious instance launch", "Unauthorized function creation"], "data_sources": ["Activity Tracker", "Code Engine Logs"]},
        "rem": {"immediate": ["Terminate suspicious instances", "Delete unauthorized functions"], "preventive": ["Restrict compute creation to approved images", "Use trusted profiles for workloads"], "ibm_services": ["VPC", "Code Engine", "Security Advisor"]},
    },
    "T1490": {
        "det": {"activity_tracker_events": ["backup-recovery.backup-policy.delete", "is.snapshot.snapshot.delete", "cloud-databases.backup.delete"], "security_advisor_findings": ["Backup deletion detected", "Recovery inhibition activity"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Restore from remaining backups", "Block the deleting principal"], "preventive": ["Enable backup retention locks", "Use cross-region backups", "Restrict DeleteBackup permissions"], "ibm_services": ["Backup Recovery", "Cloud Databases", "Security Advisor"]},
    },
    "T1491": {
        "det": {"activity_tracker_events": ["internet-services.waf-rule.update", "cloud-object-storage.object.put"], "security_advisor_findings": ["Web application content modified", "Unauthorized content change"], "data_sources": ["Activity Tracker", "CIS Logs"]},
        "rem": {"immediate": ["Revert content from backups", "Block attacker access"], "preventive": ["Enable WAF protection via CIS", "Use versioning on COS", "Content integrity monitoring"], "ibm_services": ["Cloud Internet Services", "Cloud Object Storage", "Security Advisor"]},
    },
    "T1498": {
        "det": {"activity_tracker_events": ["internet-services.rate-limit.trigger", "is.security-group.security-group.update"], "security_advisor_findings": ["DDoS pattern detected", "Volumetric attack"], "data_sources": ["CIS Logs", "VPC Flow Logs"]},
        "rem": {"immediate": ["Enable DDoS protection", "Block attack sources"], "preventive": ["Use CIS with DDoS protection", "Configure rate limiting", "Deploy load balancers"], "ibm_services": ["Cloud Internet Services", "VPC Load Balancer", "Security Advisor"]},
    },
    "T1499": {
        "det": {"activity_tracker_events": ["is.load-balancer.load-balancer.update", "code-engine.application.scale"], "security_advisor_findings": ["Application-layer DoS detected", "Service degradation"], "data_sources": ["CIS Logs", "Load Balancer Logs"]},
        "rem": {"immediate": ["Scale resources", "Enable bot management"], "preventive": ["Configure rate limiting", "Use autoscaling", "Deploy CDN"], "ibm_services": ["Cloud Internet Services", "VPC Load Balancer", "Code Engine"]},
    },
    "T1525": {
        "det": {"activity_tracker_events": ["container-registry.image.push", "container-registry.image.scan"], "security_advisor_findings": ["Unscanned container image deployed", "Vulnerable image pushed"], "data_sources": ["Activity Tracker", "Container Registry Logs"]},
        "rem": {"immediate": ["Remove compromised images", "Redeploy from trusted images"], "preventive": ["Enable VA scanning in Container Registry", "Enforce image pull policies", "Use Portieris for image signing"], "ibm_services": ["Container Registry", "Vulnerability Advisor", "Portieris"]},
    },
    "T1526": {
        "det": {"activity_tracker_events": ["resource-catalog.instance.list", "is.instance.instance.list", "cloud-object-storage.bucket.list"], "security_advisor_findings": ["Cloud service enumeration detected", "Bulk resource listing"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Investigate enumeration source", "Check for compromised credentials"], "preventive": ["Restrict List permissions", "Use resource groups for isolation", "Enable Security Advisor"], "ibm_services": ["IAM", "Resource Groups", "Security Advisor"]},
    },
    "T1531": {
        "det": {"activity_tracker_events": ["iam-identity.user.delete", "iam-identity.apikey.delete", "iam-identity.serviceid.delete"], "security_advisor_findings": ["Account access removal detected", "Critical IAM deletion"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Restore deleted users/keys", "Re-create service IDs"], "preventive": ["Restrict IAM deletion permissions", "Alert on destructive IAM actions", "Use break-glass procedures"], "ibm_services": ["IAM", "Event Notifications", "Security Advisor"]},
    },
    "T1535": {
        "det": {"activity_tracker_events": ["is.instance.instance.create", "cloud-object-storage.bucket.create"], "security_advisor_findings": ["Resource created in unusual region", "Activity in non-standard MZR"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Terminate resources in unauthorized regions", "Investigate the creating identity"], "preventive": ["Restrict account to approved MZRs", "Alert on resource creation in non-standard regions"], "ibm_services": ["IAM", "Event Notifications", "Security Advisor"]},
    },
    "T1537": {
        "det": {"activity_tracker_events": ["cloud-object-storage.bucket.create_replication", "transit.gateway.connection.create"], "security_advisor_findings": ["Cross-account data transfer detected", "COS replication to external destination"], "data_sources": ["Activity Tracker", "COS Logs"]},
        "rem": {"immediate": ["Remove unauthorized replication", "Block external account access"], "preventive": ["Restrict cross-account policies", "Monitor data transfer destinations", "Use private endpoints"], "ibm_services": ["Cloud Object Storage", "IAM", "Security Advisor"]},
    },
    "T1538": {
        "det": {"activity_tracker_events": ["resource-catalog.dashboard.read", "iam-identity.account-settings.read"], "security_advisor_findings": ["Dashboard enumeration detected"], "data_sources": ["Activity Tracker"]},
        "rem": {"immediate": ["Review console/dashboard access", "Check for unauthorized sessions"], "preventive": ["Enforce MFA for console access", "Restrict account-level read permissions"], "ibm_services": ["IAM", "Console", "Security Advisor"]},
    },
    "T1550": {
        "det": {"activity_tracker_events": ["iam-identity.apikey.create", "iam-identity.token.create"], "security_advisor_findings": ["Token reuse from unusual location", "Alternate credential detected"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Revoke suspicious tokens/API keys", "Rotate credentials"], "preventive": ["Use short-lived tokens via trusted profiles", "Enforce IP restrictions", "Enable MFA"], "ibm_services": ["IAM", "Security Advisor", "Activity Tracker"]},
    },
    "T1552.005": {
        "det": {"activity_tracker_events": ["is.instance.metadata.read"], "security_advisor_findings": ["Instance metadata API abuse", "SSRF targeting metadata"], "data_sources": ["Activity Tracker", "Instance Logs"]},
        "rem": {"immediate": ["Rotate instance profile credentials", "Block metadata access from containers"], "preventive": ["Use trusted profiles instead of metadata credentials", "Restrict metadata endpoint access", "Use VPC endpoint for IAM"], "ibm_services": ["VPC Compute", "IAM Trusted Profiles", "Security Advisor"]},
    },
    "T1556": {
        "det": {"activity_tracker_events": ["iam-identity.idp.update", "iam-identity.account-settings.update"], "security_advisor_findings": ["Authentication flow modified", "Identity provider changed"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Revert authentication changes", "Review IdP configurations"], "preventive": ["Alert on auth config changes", "Restrict IdP modification permissions", "Regular federation audits"], "ibm_services": ["IAM", "App ID", "Security Advisor"]},
    },
    "T1562.008": {
        "det": {"activity_tracker_events": ["log-analysis.dashboard.delete", "atracker.target.delete", "activity-tracker.route.delete"], "security_advisor_findings": ["Logging disabled", "Activity Tracker configuration modified"], "data_sources": ["Activity Tracker", "Log Analysis"]},
        "rem": {"immediate": ["Re-enable disabled logging", "Restore Activity Tracker routes"], "preventive": ["Restrict logging deletion permissions", "Archive logs to COS", "Alert on logging config changes"], "ibm_services": ["Activity Tracker", "Log Analysis", "Event Notifications"]},
    },
    "T1578": {
        "det": {"activity_tracker_events": ["is.instance.instance.update", "is.image.image.create", "is.instance.instance.create"], "security_advisor_findings": ["Compute infrastructure modification", "Unauthorized instance cloning"], "data_sources": ["Activity Tracker", "Security Advisor"]},
        "rem": {"immediate": ["Revert unauthorized changes", "Terminate cloned instances"], "preventive": ["Restrict compute modification permissions", "Use resource groups for isolation", "Enable Security Advisor compute insights"], "ibm_services": ["VPC Compute", "IAM", "Security Advisor"]},
    },
    "T1606": {
        "det": {"activity_tracker_events": ["iam-identity.apikey.create", "appid.token.create"], "security_advisor_findings": ["Suspicious credential forging", "Token anomaly"], "data_sources": ["Activity Tracker", "App ID Logs"]},
        "rem": {"immediate": ["Revoke forged credentials", "Reset affected identity providers"], "preventive": ["Use short-lived tokens", "Monitor token issuance", "Enforce strict OIDC validation via App ID"], "ibm_services": ["IAM", "App ID", "Security Advisor"]},
    },
}

# ── Alicloud Guidance for 28 gap techniques ─────────────────────────────
ALICLOUD_GUIDANCE = {
    "T1040": {
        "det": {"actiontrail_events": ["CreateFlowLog", "DescribeEipAddresses", "DescribeNetworkInterfaces"], "security_center_alerts": ["Network packet capture detected", "Unusual VPC traffic monitoring"], "data_sources": ["ActionTrail", "VPC Flow Logs"]},
        "rem": {"immediate": ["Review flow log destinations", "Check for unauthorized captures"], "preventive": ["Enable VPC flow logs", "Restrict security group rules"], "alicloud_services": ["VPC Flow Logs", "Security Center", "Security Groups"]},
    },
    "T1046": {
        "det": {"actiontrail_events": ["DescribeInstances", "DescribeSecurityGroups", "DescribeVSwitches"], "security_center_alerts": ["Port scanning detected", "Network reconnaissance"], "data_sources": ["ActionTrail", "VPC Flow Logs"]},
        "rem": {"immediate": ["Block scanning IPs", "Review security group rules"], "preventive": ["Minimize open ports", "Use Cloud Firewall", "Enable Security Center network detection"], "alicloud_services": ["Cloud Firewall", "Security Center", "Security Groups"]},
    },
    "T1048": {
        "det": {"actiontrail_events": ["PutBucketReplication", "GetObject", "DescribeBandwidthPackages"], "security_center_alerts": ["Unusual data transfer", "Large outbound movement"], "data_sources": ["ActionTrail", "OSS Access Logs"]},
        "rem": {"immediate": ["Block unauthorized egress", "Review OSS replication"], "preventive": ["Restrict outbound security group rules", "Monitor data transfer", "Use VPC endpoints for OSS"], "alicloud_services": ["Object Storage Service", "Cloud Firewall", "Security Center"]},
    },
    "T1049": {
        "det": {"actiontrail_events": ["DescribeVpcs", "DescribeVSwitches", "DescribeSecurityGroupAttribute"], "security_center_alerts": ["Network enumeration detected"], "data_sources": ["ActionTrail", "VPC Flow Logs"]},
        "rem": {"immediate": ["Review RAM policies for network discovery", "Check for unauthorized access"], "preventive": ["Apply least-privilege RAM policies", "Enable Security Center"], "alicloud_services": ["RAM", "Security Center", "VPC"]},
    },
    "T1059": {
        "det": {"actiontrail_events": ["RunCommand", "InvokeFunction", "CreateCommand"], "security_center_alerts": ["Suspicious command execution", "Unauthorized function invocation"], "data_sources": ["ActionTrail", "Function Compute Logs"]},
        "rem": {"immediate": ["Terminate suspicious commands", "Review function invocations"], "preventive": ["Restrict RunCommand permissions in RAM", "Use Cloud Assistant with approval workflows"], "alicloud_services": ["Cloud Assistant", "Function Compute", "Security Center"]},
    },
    "T1069": {
        "det": {"actiontrail_events": ["ListGroups", "ListGroupsForUser", "GetGroup"], "security_center_alerts": ["RAM group enumeration detected"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Investigate group enumeration source", "Check for compromised keys"], "preventive": ["Restrict ListGroups RAM permissions", "Enable Security Center RAM insights"], "alicloud_services": ["RAM", "Security Center", "ActionTrail"]},
    },
    "T1087": {
        "det": {"actiontrail_events": ["ListUsers", "ListAccessKeys", "GetUser"], "security_center_alerts": ["User account enumeration", "Bulk access key listing"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Investigate bulk user listing", "Rotate compromised access keys"], "preventive": ["Restrict user listing in RAM", "Use STS temporary credentials"], "alicloud_services": ["RAM", "Security Center", "ActionTrail"]},
    },
    "T1119": {
        "det": {"actiontrail_events": ["GetObject", "ListObjects", "GetBucketInfo"], "security_center_alerts": ["Automated data collection from OSS", "Bulk object access"], "data_sources": ["ActionTrail", "OSS Access Logs"]},
        "rem": {"immediate": ["Review bulk access patterns", "Rotate affected credentials"], "preventive": ["Enable OSS access logging", "Apply lifecycle rules", "Use STS tokens with expiration"], "alicloud_services": ["Object Storage Service", "Security Center", "RAM"]},
    },
    "T1136": {
        "det": {"actiontrail_events": ["CreateUser", "CreateGroup", "CreateRole"], "security_center_alerts": ["Unauthorized user creation", "New RAM user with broad permissions"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Delete unauthorized users", "Review associated RAM policies"], "preventive": ["Use STS roles instead of users", "Alert on CreateUser events", "Enforce resource tagging"], "alicloud_services": ["RAM", "Security Center", "EventBridge"]},
    },
    "T1199": {
        "det": {"actiontrail_events": ["CreateRole", "SetRoleTrustPolicy", "AssumeRole"], "security_center_alerts": ["Cross-account role assumption", "New trust relationship created"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Audit cross-account role trust policies", "Review AssumeRole patterns"], "preventive": ["Minimize cross-account trust", "Use resource directory for isolation"], "alicloud_services": ["RAM", "Resource Directory", "Security Center"]},
    },
    "T1201": {
        "det": {"actiontrail_events": ["GetPasswordPolicy", "GetSecurityPreference"], "security_center_alerts": ["Password policy enumeration"], "data_sources": ["ActionTrail"]},
        "rem": {"immediate": ["Check who queried password policy", "Verify settings unchanged"], "preventive": ["Enforce strong password policy", "Enable MFA"], "alicloud_services": ["RAM", "Security Center"]},
    },
    "T1204": {
        "det": {"actiontrail_events": ["CreateInstance", "CreateFunction", "InvokeFunction"], "security_center_alerts": ["Suspicious instance launch", "Unauthorized function creation"], "data_sources": ["ActionTrail", "Function Compute Logs"]},
        "rem": {"immediate": ["Terminate suspicious instances", "Delete unauthorized functions"], "preventive": ["Restrict instance creation to approved images", "Use custom images only"], "alicloud_services": ["ECS", "Function Compute", "Security Center"]},
    },
    "T1490": {
        "det": {"actiontrail_events": ["DeleteBackupPlan", "DeleteSnapshot", "DeleteDBInstance"], "security_center_alerts": ["Backup deletion detected", "Recovery inhibition"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Restore from remaining backups", "Block the deleting principal"], "preventive": ["Enable backup retention", "Use cross-region backup", "Restrict delete permissions"], "alicloud_services": ["HBR", "RDS Backup", "Security Center"]},
    },
    "T1491": {
        "det": {"actiontrail_events": ["SetDomainServerCertificate", "PutObject", "SetWafConfig"], "security_center_alerts": ["Web defacement detected", "Content modification"], "data_sources": ["ActionTrail", "WAF Logs", "OSS Logs"]},
        "rem": {"immediate": ["Revert content from backups", "Block attacker"], "preventive": ["Enable WAF protection", "Use OSS versioning", "Content integrity monitoring"], "alicloud_services": ["WAF", "Object Storage Service", "Security Center"]},
    },
    "T1498": {
        "det": {"actiontrail_events": ["ModifySecurityGroupRule", "DescribeDDoSEvents"], "security_center_alerts": ["DDoS pattern detected", "Volumetric attack"], "data_sources": ["Anti-DDoS Logs", "VPC Flow Logs"]},
        "rem": {"immediate": ["Enable Anti-DDoS", "Block attack sources"], "preventive": ["Use Anti-DDoS Premium", "Configure rate limiting", "Deploy SLB with DDoS protection"], "alicloud_services": ["Anti-DDoS", "SLB", "Security Center"]},
    },
    "T1499": {
        "det": {"actiontrail_events": ["SetLoadBalancerStatus", "DescribeHealthStatus"], "security_center_alerts": ["Application-layer DoS", "Service degradation"], "data_sources": ["WAF Logs", "SLB Logs"]},
        "rem": {"immediate": ["Scale resources", "Enable bot management"], "preventive": ["Configure WAF rate limiting", "Use auto scaling", "Deploy CDN"], "alicloud_services": ["WAF", "SLB", "Auto Scaling", "CDN"]},
    },
    "T1525": {
        "det": {"actiontrail_events": ["PushImage", "CreateContainerRegistryNamespace"], "security_center_alerts": ["Unscanned container image", "Vulnerable image pushed"], "data_sources": ["ActionTrail", "Container Registry Logs"]},
        "rem": {"immediate": ["Remove compromised images", "Redeploy from trusted images"], "preventive": ["Enable image scanning in ACR", "Use signed images", "Enforce image pull policies"], "alicloud_services": ["Container Registry", "Container Service", "Security Center"]},
    },
    "T1526": {
        "det": {"actiontrail_events": ["DescribeInstances", "ListBuckets", "DescribeDBInstances"], "security_center_alerts": ["Cloud service enumeration", "Bulk resource listing"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Investigate enumeration source", "Check for compromised credentials"], "preventive": ["Restrict List/Describe permissions in RAM", "Use resource groups"], "alicloud_services": ["RAM", "Resource Groups", "Security Center"]},
    },
    "T1531": {
        "det": {"actiontrail_events": ["DeleteUser", "RemoveUserFromGroup", "DeleteAccessKey"], "security_center_alerts": ["Account access removal", "Critical RAM deletion"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Restore deleted users/keys", "Re-grant removed permissions"], "preventive": ["Restrict RAM deletion permissions", "Alert on destructive actions", "Use break-glass procedures"], "alicloud_services": ["RAM", "EventBridge", "Security Center"]},
    },
    "T1535": {
        "det": {"actiontrail_events": ["CreateInstance", "CreateBucket", "CreateDBInstance"], "security_center_alerts": ["Resource created in unusual region"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Terminate resources in unauthorized regions", "Investigate creator"], "preventive": ["Use RAM policies to restrict regions", "Alert on non-standard region usage"], "alicloud_services": ["RAM", "EventBridge", "Security Center"]},
    },
    "T1537": {
        "det": {"actiontrail_events": ["PutBucketReplication", "AssumeRole"], "security_center_alerts": ["Cross-account data transfer", "OSS replication to external"], "data_sources": ["ActionTrail", "OSS Logs"]},
        "rem": {"immediate": ["Remove unauthorized replication", "Block external account access"], "preventive": ["Restrict cross-account RAM policies", "Monitor transfer destinations"], "alicloud_services": ["Object Storage Service", "RAM", "Security Center"]},
    },
    "T1538": {
        "det": {"actiontrail_events": ["DescribeAccountAttributes", "GetSecurityPreference"], "security_center_alerts": ["Console enumeration detected"], "data_sources": ["ActionTrail"]},
        "rem": {"immediate": ["Review console access", "Check for unauthorized sessions"], "preventive": ["Enforce MFA for console", "Restrict account-level read permissions"], "alicloud_services": ["RAM", "Console", "Security Center"]},
    },
    "T1550": {
        "det": {"actiontrail_events": ["CreateAccessKey", "AssumeRole", "GetCallerIdentity"], "security_center_alerts": ["Token reuse from unusual location", "Alternate credential"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Revoke suspicious tokens/keys", "Rotate credentials"], "preventive": ["Use STS temporary credentials", "Enforce IP restrictions", "Enable MFA"], "alicloud_services": ["RAM", "STS", "Security Center"]},
    },
    "T1552.005": {
        "det": {"actiontrail_events": ["DescribeInstanceRamRole"], "security_center_alerts": ["Instance metadata abuse", "SSRF targeting metadata"], "data_sources": ["ActionTrail", "ECS Logs"]},
        "rem": {"immediate": ["Rotate RAM role credentials", "Block metadata from containers"], "preventive": ["Use instance RAM roles with minimal permissions", "Restrict metadata access", "Enable Security Center agent"], "alicloud_services": ["ECS", "RAM", "Security Center"]},
    },
    "T1556": {
        "det": {"actiontrail_events": ["SetSecurityPreference", "CreateSAMLProvider", "UpdateSAMLProvider"], "security_center_alerts": ["Authentication flow modified", "SSO provider changed"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Revert authentication changes", "Review SAML providers"], "preventive": ["Alert on auth config changes", "Restrict SAML provider permissions", "Regular SSO audits"], "alicloud_services": ["RAM SSO", "Security Center", "EventBridge"]},
    },
    "T1562.008": {
        "det": {"actiontrail_events": ["StopLogging", "DeleteTrail", "DeleteLogProject"], "security_center_alerts": ["Logging disabled", "ActionTrail configuration modified"], "data_sources": ["ActionTrail", "SLS"]},
        "rem": {"immediate": ["Re-enable logging", "Restore ActionTrail configuration"], "preventive": ["Restrict logging deletion permissions", "Archive to OSS", "Alert on config changes"], "alicloud_services": ["ActionTrail", "SLS", "EventBridge"]},
    },
    "T1578": {
        "det": {"actiontrail_events": ["ModifyInstanceAttribute", "CreateImage", "RunInstances"], "security_center_alerts": ["Compute modification", "Unauthorized instance cloning"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Revert unauthorized changes", "Terminate cloned instances"], "preventive": ["Restrict compute modification in RAM", "Use resource groups", "Enable Security Center"], "alicloud_services": ["ECS", "RAM", "Security Center"]},
    },
    "T1606": {
        "det": {"actiontrail_events": ["CreateAccessKey", "AssumeRoleWithSAML"], "security_center_alerts": ["Suspicious credential forging", "SAML assertion anomaly"], "data_sources": ["ActionTrail", "Security Center"]},
        "rem": {"immediate": ["Revoke forged credentials", "Reset SAML providers"], "preventive": ["Use STS with short TTL", "Monitor token issuance", "Enforce strict SAML validation"], "alicloud_services": ["RAM", "STS", "Security Center"]},
    },
}

# ── K8s Guidance for 28 gap techniques ──────────────────────────────────
K8S_GUIDANCE = {
    "T1040": {
        "det": {"audit_logs": ["create pods with NET_RAW capability", "create privileged pods", "hostNetwork pod creation"], "falco_alerts": ["Packet capture tool detected", "Container with NET_RAW capability"], "data_sources": ["K8s Audit Logs", "Falco", "Network Policy Logs"]},
        "rem": {"immediate": ["Delete pods with NET_RAW capability", "Review network policies"], "preventive": ["Drop NET_RAW capability via PodSecurityStandard", "Enforce NetworkPolicy", "Use service mesh with mTLS"], "k8s_services": ["PodSecurityStandard", "NetworkPolicy", "Service Mesh"]},
    },
    "T1046": {
        "det": {"audit_logs": ["list services", "list endpoints", "get pods with IP"], "falco_alerts": ["Port scanning from container", "Network discovery tool detected"], "data_sources": ["K8s Audit Logs", "Falco", "CNI Logs"]},
        "rem": {"immediate": ["Isolate scanning pod via NetworkPolicy", "Review pod privileges"], "preventive": ["Default-deny NetworkPolicy per namespace", "Restrict service listing RBAC", "Use network segmentation"], "k8s_services": ["NetworkPolicy", "RBAC", "CNI"]},
    },
    "T1048": {
        "det": {"audit_logs": ["create pod with hostNetwork", "patch service external-ips"], "falco_alerts": ["Outbound connection to unusual port", "DNS tunneling detected"], "data_sources": ["K8s Audit Logs", "Falco", "CNI Flow Logs"]},
        "rem": {"immediate": ["Kill exfiltrating pod", "Block egress via NetworkPolicy"], "preventive": ["Default-deny egress NetworkPolicy", "Use DNS policy restrictions", "Monitor outbound traffic patterns"], "k8s_services": ["NetworkPolicy", "Falco", "DNS Policy"]},
    },
    "T1049": {
        "det": {"audit_logs": ["list services", "list pods", "list endpoints", "get nodes"], "falco_alerts": ["Container network enumeration", "Internal service discovery"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Review RBAC for listing permissions", "Check for compromised service accounts"], "preventive": ["Restrict list/get RBAC per namespace", "Use NetworkPolicy to limit DNS"], "k8s_services": ["RBAC", "NetworkPolicy", "Falco"]},
    },
    "T1069": {
        "det": {"audit_logs": ["list clusterroles", "list clusterrolebindings", "list rolebindings"], "falco_alerts": ["RBAC enumeration detected", "Bulk role listing"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Investigate enumeration source", "Check for compromised tokens"], "preventive": ["Restrict RBAC listing to admins only", "Enable audit logging for RBAC reads"], "k8s_services": ["RBAC", "Audit Logging", "Falco"]},
    },
    "T1087": {
        "det": {"audit_logs": ["list serviceaccounts", "get serviceaccount", "list users"], "falco_alerts": ["Service account enumeration", "Bulk token listing"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Investigate bulk SA listing", "Rotate compromised tokens"], "preventive": ["Restrict SA listing RBAC", "Disable auto-mount of SA tokens", "Use projected volume tokens"], "k8s_services": ["RBAC", "Service Accounts", "Falco"]},
    },
    "T1119": {
        "det": {"audit_logs": ["get secrets", "list configmaps", "exec into pods"], "falco_alerts": ["Automated secret collection", "Bulk configmap access"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Rotate exposed secrets", "Review exec permissions"], "preventive": ["Restrict secret/configmap access RBAC", "Use external secret stores (Vault)", "Encrypt secrets at rest"], "k8s_services": ["RBAC", "External Secrets", "Encryption"]},
    },
    "T1136": {
        "det": {"audit_logs": ["create serviceaccount", "create clusterrolebinding", "create rolebinding"], "falco_alerts": ["Unauthorized service account creation", "New admin-level binding"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Delete unauthorized SAs/bindings", "Review associated roles"], "preventive": ["Restrict SA creation RBAC", "Use OPA/Gatekeeper to enforce policies", "Alert on new cluster-admin bindings"], "k8s_services": ["RBAC", "OPA Gatekeeper", "Falco"]},
    },
    "T1199": {
        "det": {"audit_logs": ["create federation resource", "create cross-cluster secret", "update kubeconfig"], "falco_alerts": ["Cross-cluster access detected", "Federation trust created"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Review cross-cluster configs", "Revoke unauthorized federation"], "preventive": ["Minimize cross-cluster trust", "Use workload identity federation", "Audit OIDC providers"], "k8s_services": ["Federation", "Workload Identity", "RBAC"]},
    },
    "T1201": {
        "det": {"audit_logs": ["get authentication configuration", "describe oidc-provider"], "falco_alerts": ["Authentication policy enumeration"], "data_sources": ["K8s Audit Logs"]},
        "rem": {"immediate": ["Check who queried auth config", "Verify OIDC settings unchanged"], "preventive": ["Restrict auth config reading RBAC", "Use external IdP with MFA"], "k8s_services": ["RBAC", "OIDC", "Falco"]},
    },
    "T1204": {
        "det": {"audit_logs": ["create deployment", "create pod", "apply manifest"], "falco_alerts": ["Pod created from untrusted image", "Deployment with suspicious image"], "data_sources": ["K8s Audit Logs", "Falco", "Admission Logs"]},
        "rem": {"immediate": ["Delete suspicious pods/deployments", "Review image provenance"], "preventive": ["Use admission controllers to validate images", "Enable image signing (cosign)", "Restrict to approved registries"], "k8s_services": ["Admission Controllers", "Image Signing", "OPA Gatekeeper"]},
    },
    "T1490": {
        "det": {"audit_logs": ["delete persistentvolumeclaim", "delete velero backup", "delete etcd snapshot"], "falco_alerts": ["Backup deletion detected", "PVC deletion in production namespace"], "data_sources": ["K8s Audit Logs", "Falco", "Velero Logs"]},
        "rem": {"immediate": ["Restore from remaining backups", "Block the deleting identity"], "preventive": ["Use Velero with immutable backups", "Restrict PVC deletion RBAC", "Cross-cluster backup replication"], "k8s_services": ["Velero", "RBAC", "etcd Backup"]},
    },
    "T1491": {
        "det": {"audit_logs": ["update configmap", "patch deployment", "update ingress"], "falco_alerts": ["Web content modification", "ConfigMap containing HTML modified"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Revert modified configs from git", "Redeploy from known-good state"], "preventive": ["Use GitOps (ArgoCD/Flux) for config management", "Restrict configmap updates RBAC", "Content integrity checks"], "k8s_services": ["GitOps", "RBAC", "Falco"]},
    },
    "T1498": {
        "det": {"audit_logs": ["scale deployment", "update service load-balancer"], "falco_alerts": ["DDoS pattern detected", "Volumetric traffic to service"], "data_sources": ["K8s Audit Logs", "Ingress Logs", "CNI Flow Logs"]},
        "rem": {"immediate": ["Scale replicas", "Enable rate limiting on ingress"], "preventive": ["Use ingress with rate limiting", "Configure HPA for auto-scaling", "Deploy WAF in front of ingress"], "k8s_services": ["Ingress Controller", "HPA", "WAF"]},
    },
    "T1499": {
        "det": {"audit_logs": ["scale deployment", "get pod status"], "falco_alerts": ["Application-layer DoS", "Pod crashlooping due to external traffic"], "data_sources": ["K8s Audit Logs", "Ingress Logs"]},
        "rem": {"immediate": ["Scale resources", "Enable circuit breakers"], "preventive": ["Configure resource limits/requests", "Use HPA", "Implement circuit breaker patterns"], "k8s_services": ["HPA", "Resource Quotas", "Service Mesh"]},
    },
    "T1526": {
        "det": {"audit_logs": ["list namespaces", "list pods --all-namespaces", "get cluster-info"], "falco_alerts": ["Cluster enumeration detected", "Cross-namespace resource listing"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Investigate enumeration source", "Check for compromised SA tokens"], "preventive": ["Restrict cluster-wide listing RBAC", "Namespace-scoped roles only", "Enable Falco rules for recon"], "k8s_services": ["RBAC", "Namespaces", "Falco"]},
    },
    "T1531": {
        "det": {"audit_logs": ["delete serviceaccount", "delete rolebinding", "delete clusterrolebinding"], "falco_alerts": ["Access removal detected", "Critical RBAC deletion"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Restore deleted SAs/bindings", "Re-apply RBAC from git"], "preventive": ["Use GitOps for RBAC management", "Restrict delete RBAC", "Alert on binding deletions"], "k8s_services": ["GitOps", "RBAC", "Falco"]},
    },
    "T1535": {
        "det": {"audit_logs": ["create namespace", "create pod in non-standard namespace"], "falco_alerts": ["Resource in unusual namespace", "Workload in system namespace"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Delete resources in unauthorized namespaces", "Investigate creator"], "preventive": ["Use ResourceQuotas per namespace", "OPA constraints for allowed namespaces", "Alert on new namespace creation"], "k8s_services": ["ResourceQuotas", "OPA Gatekeeper", "Falco"]},
    },
    "T1537": {
        "det": {"audit_logs": ["create pod with volume mount to external", "patch secret with external endpoint"], "falco_alerts": ["Data transfer to external endpoint", "Volume mount to unknown destination"], "data_sources": ["K8s Audit Logs", "Falco", "CNI Flow Logs"]},
        "rem": {"immediate": ["Kill exfiltrating pod", "Remove external volume mounts"], "preventive": ["Restrict volume mount types via PSS", "Default-deny egress NetworkPolicy", "Monitor external connections"], "k8s_services": ["PodSecurityStandard", "NetworkPolicy", "Falco"]},
    },
    "T1538": {
        "det": {"audit_logs": ["access kubernetes dashboard", "get cluster-info", "proxy requests"], "falco_alerts": ["Dashboard access detected", "kubectl proxy started"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Review dashboard access logs", "Check for exposed dashboard"], "preventive": ["Disable K8s dashboard in production", "Enforce RBAC on dashboard", "Use kubectl with audit logging"], "k8s_services": ["RBAC", "Audit Logging", "Falco"]},
    },
    "T1550": {
        "det": {"audit_logs": ["create token", "use bootstrap token", "authenticate with stolen token"], "falco_alerts": ["Token reuse from unusual source", "Stolen SA token usage"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Revoke suspicious tokens", "Rotate SA tokens"], "preventive": ["Use short-lived projected tokens", "Disable auto-mount of SA tokens", "Enable TokenRequest API"], "k8s_services": ["TokenRequest", "RBAC", "Falco"]},
    },
    "T1552.005": {
        "det": {"audit_logs": ["pod with hostNetwork accessing metadata", "curl to 169.254.169.254 from pod"], "falco_alerts": ["Metadata endpoint access from container", "SSRF to cloud metadata"], "data_sources": ["K8s Audit Logs", "Falco", "CNI Logs"]},
        "rem": {"immediate": ["Kill pod accessing metadata", "Rotate cloud credentials"], "preventive": ["Block metadata access via NetworkPolicy", "Use workload identity instead of node credentials", "Enforce IMDSv2 on nodes"], "k8s_services": ["NetworkPolicy", "Workload Identity", "Falco"]},
    },
    "T1556": {
        "det": {"audit_logs": ["update authentication config", "create webhook token review", "modify oidc-issuer"], "falco_alerts": ["Authentication configuration modified", "Webhook authenticator changed"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Revert auth config changes", "Review webhook configurations"], "preventive": ["Restrict auth config modification RBAC", "Use managed K8s auth (EKS/GKE)", "Audit auth config changes"], "k8s_services": ["RBAC", "Authentication", "Falco"]},
    },
    "T1562.008": {
        "det": {"audit_logs": ["delete falco daemonset", "modify audit policy", "delete fluentd/fluentbit"], "falco_alerts": ["Audit logging disabled", "Security agent removed"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Restore deleted security agents", "Re-enable audit logging"], "preventive": ["Protect security namespace with RBAC", "Use immutable containers for agents", "Alert on security agent changes"], "k8s_services": ["Falco", "Audit Logging", "OPA Gatekeeper"]},
    },
    "T1578": {
        "det": {"audit_logs": ["patch deployment image", "update statefulset", "create pod with modified spec"], "falco_alerts": ["Workload specification modified", "Container image changed unexpectedly"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Revert to known-good deployment spec", "Check for tampered images"], "preventive": ["Use GitOps for all deployments", "Enable image verification", "Restrict patch/update RBAC"], "k8s_services": ["GitOps", "Image Verification", "RBAC"]},
    },
    "T1525": {
        "det": {"audit_logs": ["create pod from untrusted registry", "push to internal registry"], "falco_alerts": ["Untrusted image deployed", "Image from unknown registry"], "data_sources": ["K8s Audit Logs", "Falco", "Admission Logs"]},
        "rem": {"immediate": ["Delete pods with compromised images", "Remove tainted images from registry"], "preventive": ["Use admission controller to enforce trusted registries", "Enable image scanning (Trivy)", "Require image signatures (cosign)"], "k8s_services": ["Admission Controllers", "Trivy", "cosign"]},
    },
    "T1606": {
        "det": {"audit_logs": ["create token request", "create secret type kubernetes.io/service-account-token"], "falco_alerts": ["Token forging detected", "Long-lived SA token created"], "data_sources": ["K8s Audit Logs", "Falco"]},
        "rem": {"immediate": ["Revoke forged tokens", "Rotate affected SA credentials"], "preventive": ["Use bound SA tokens (projected volumes)", "Disable legacy token creation", "Short TTL on tokens"], "k8s_services": ["TokenRequest API", "RBAC", "Falco"]},
    },
}

ALL_CSP_GUIDANCE = {
    "oci": OCI_GUIDANCE,
    "ibm": IBM_GUIDANCE,
    "alicloud": ALICLOUD_GUIDANCE,
    "k8s": K8S_GUIDANCE,
}


def seed_csp_guidance(conn, csp_name: str, guidance: dict, dry_run: bool = False):
    """Merge CSP-specific guidance into existing mitre_technique_reference rows."""
    updated = 0
    skipped = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for tech_id, data in sorted(guidance.items()):
            # Check if technique exists and already has this CSP
            cur.execute("""
                SELECT technique_id, technique_name,
                       detection_guidance, remediation_guidance
                FROM mitre_technique_reference
                WHERE technique_id = %s
            """, (tech_id,))
            row = cur.fetchone()

            if not row:
                print(f"  SKIP (not found): {tech_id}")
                skipped += 1
                continue

            orig_det = row["detection_guidance"] or {}
            orig_rem = row["remediation_guidance"] or {}

            if csp_name in orig_det:
                if dry_run:
                    print(f"  EXISTS: {tech_id} — {row['technique_name']} already has {csp_name}")
                skipped += 1
                continue

            if dry_run:
                print(f"  WOULD ADD: {tech_id} — {row['technique_name']} += {csp_name}")
                updated += 1
                continue

            # Merge CSP section into JSONB
            cur.execute("""
                UPDATE mitre_technique_reference
                SET detection_guidance = detection_guidance || jsonb_build_object(%s, %s::jsonb),
                    remediation_guidance = remediation_guidance || jsonb_build_object(%s, %s::jsonb),
                    updated_at = NOW()
                WHERE technique_id = %s
            """, (
                csp_name, json.dumps(data["det"]),
                csp_name, json.dumps(data["rem"]),
                tech_id,
            ))
            print(f"  UPDATED: {tech_id} — {row['technique_name']} += {csp_name}")
            updated += 1

    if not dry_run:
        conn.commit()

    return updated, skipped


def verify_coverage(conn):
    """Show coverage report per CSP."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        checks = [
            ("Total", "SELECT COUNT(*) FROM mitre_technique_reference"),
            ("AWS", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'cloudtrail_events'"),
            ("Azure", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'azure'"),
            ("GCP", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'gcp'"),
            ("OCI", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'oci'"),
            ("IBM", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'ibm'"),
            ("Alicloud", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'alicloud'"),
            ("K8s", "SELECT COUNT(*) FROM mitre_technique_reference WHERE detection_guidance ? 'k8s'"),
        ]

        print(f"\n{'CSP':<12} {'Techniques':>10}  Coverage")
        print("-" * 50)
        total = 0
        for label, sql in checks:
            cur.execute(sql)
            cnt = cur.fetchone()["count"]
            if label == "Total":
                total = cnt
                print(f"{'Total':<12} {cnt:>10}")
                print("-" * 50)
            else:
                bar = "█" * int(cnt / max(total, 1) * 30)
                pct = cnt / max(total, 1) * 100
                print(f"{label:<12} {cnt:>10}  {bar} {pct:.0f}%")


def main():
    parser = argparse.ArgumentParser(description="Expand MITRE guidance for OCI/IBM/Alicloud/K8s (v2 gap fill)")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument("--csp", choices=["oci", "ibm", "alicloud", "k8s"], help="Process single CSP")
    parser.add_argument("--verify-only", action="store_true", help="Only show coverage report")
    args = parser.parse_args()

    conn = get_conn()

    if args.verify_only:
        verify_coverage(conn)
        conn.close()
        return

    csps = [args.csp] if args.csp else ["oci", "ibm", "alicloud", "k8s"]

    print(f"\n{'=' * 70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Expanding MITRE guidance V2 (28 gap techniques)")
    print(f"CSPs: {', '.join(csps)}")
    print(f"{'=' * 70}\n")

    grand_updated = 0
    grand_skipped = 0

    for csp in csps:
        guidance = ALL_CSP_GUIDANCE[csp]
        print(f"\n── {csp.upper()} ({len(guidance)} techniques) ──")
        updated, skipped = seed_csp_guidance(conn, csp, guidance, args.dry_run)
        grand_updated += updated
        grand_skipped += skipped
        print(f"  → {updated} updated, {skipped} skipped")

    print(f"\n{'=' * 70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Total: {grand_updated} updated, {grand_skipped} skipped")
    print(f"{'=' * 70}")

    verify_coverage(conn)
    conn.close()


if __name__ == "__main__":
    main()
