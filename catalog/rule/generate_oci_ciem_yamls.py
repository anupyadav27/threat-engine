#!/usr/bin/env python3
"""
generate_oci_ciem_yamls.py — Generate OCI CIEM log-detection rule YAMLs.

Output: catalog/rule/oci_rule_ciem/<service>/<rule_id>.yaml
Run:    python3 catalog/rule/generate_oci_ciem_yamls.py
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_DIR = ROOT / "catalog" / "rule" / "oci_rule_ciem"

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions
# source_type values: oci_audit, oci_vcn_flow, oci_db_audit, oci_k8s_audit,
#                     oci_waf, oci_cloudguard
# OCI audit service namespaces: com.oraclecloud.identitycontrolplane,
#   com.oraclecloud.computemanagement, com.oraclecloud.objectstorage,
#   com.oraclecloud.database, com.oraclecloud.networking, com.oraclecloud.kms,
#   com.oraclecloud.vault, com.oraclecloud.containerengine,
#   com.oraclecloud.logging, com.oraclecloud.events,
#   com.oraclecloud.functions, com.oraclecloud.resourcemanager,
#   com.oraclecloud.waas, com.oraclecloud.budgets, com.oraclecloud.audit
# ─────────────────────────────────────────────────────────────────────────────

RULES: list[dict[str, Any]] = [

    # ── IAM / Identity ────────────────────────────────────────────────────
    {
        "rule_id": "oci.iam.audit.create_api_key",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: API Signing Key Created for User",
        "description": "An API signing key was added to an OCI user account. API keys are long-lived credentials that allow programmatic access and should be monitored for unauthorized creation.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1098"],
        "risk_score": 78,
        "resource": "oci_identity_api_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "UploadApiKey"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.delete_api_key",
        "service": "iam", "severity": "medium",
        "title": "OCI IAM: API Signing Key Deleted",
        "description": "An API signing key was deleted from a user account. Attackers may delete keys to cover tracks after rotating to a newly created key.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1070"],
        "risk_score": 60,
        "resource": "oci_identity_api_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "DeleteApiKey"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.create_auth_token",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: Auth Token Created for User",
        "description": "An auth token was created for an OCI user. Auth tokens authenticate to Oracle services (Object Storage, OCIR) and can be exfiltrated for persistent access.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 74,
        "resource": "oci_identity_auth_token",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "CreateAuthToken"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.create_customer_secret_key",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: Customer Secret Key Created (S3-compat)",
        "description": "A customer secret key was created for S3-compatible OCI Object Storage access. These keys are equivalent to AWS access keys and should be tightly controlled.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 76,
        "resource": "oci_identity_customer_secret_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "CreateCustomerSecretKey"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.create_user",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: New User Created",
        "description": "A new OCI IAM user was created. Unauthorized user creation is a persistence technique that allows attackers to maintain access after initial credentials are rotated.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136"],
        "risk_score": 80,
        "resource": "oci_identity_user",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "CreateUser"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.delete_user",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: User Deleted",
        "description": "An OCI IAM user was deleted. Deletion of legitimate users disrupts operations and may be part of a destructive attack.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 78,
        "resource": "oci_identity_user",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "DeleteUser"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.create_group",
        "service": "iam", "severity": "medium",
        "title": "OCI IAM: New IAM Group Created",
        "description": "A new IAM group was created in OCI. Adversaries create groups and assign permissive policies to gain broad access to resources.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 68,
        "resource": "oci_identity_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "CreateGroup"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.add_user_to_group",
        "service": "iam", "severity": "high",
        "title": "OCI IAM: User Added to Group",
        "description": "A user was added to an OCI IAM group. Attackers add compromised users to privileged groups to escalate permissions.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098"],
        "risk_score": 82,
        "resource": "oci_identity_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "AddUserToGroup"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.create_policy",
        "service": "iam", "severity": "critical",
        "title": "OCI IAM: Permissive Policy Created",
        "description": "A new OCI IAM policy was created. Policies that grant broad permissions (e.g., manage all-resources) can be used for privilege escalation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 88,
        "resource": "oci_identity_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "CreatePolicy"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.update_policy",
        "service": "iam", "severity": "critical",
        "title": "OCI IAM: IAM Policy Updated",
        "description": "An OCI IAM policy was modified. Policy modifications that add 'manage' or 'use' verbs for sensitive resource types expand attacker capabilities.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 90,
        "resource": "oci_identity_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "equals", "value": "UpdatePolicy"},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.mfa_totp_device_change",
        "service": "iam", "severity": "critical",
        "title": "OCI IAM: MFA TOTP Device Modified or Removed",
        "description": "An MFA TOTP device was created, updated, or deleted for an OCI user. Removing MFA reduces account security and may indicate account takeover.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1556"],
        "risk_score": 92,
        "resource": "oci_identity_mfa_totp_device",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "in", "value": ["CreateMfaTotpDevice", "DeleteMfaTotpDevice", "GenerateTotpSeed"]},
        ]}},
    },
    {
        "rule_id": "oci.iam.audit.identity_provider_change",
        "service": "iam", "severity": "critical",
        "title": "OCI IAM: Identity Provider Modified",
        "description": "An OCI identity provider (SAML/OIDC federation) was created, updated, or deleted. Modifying federation configuration can grant external identities access to OCI.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "initial_access"],
        "mitre_techniques": ["T1484"],
        "risk_score": 93,
        "resource": "oci_identity_provider",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "in", "value": ["CreateIdentityProvider", "UpdateIdentityProvider", "DeleteIdentityProvider"]},
        ]}},
    },

    # ── Compute ────────────────────────────────────────────────────────────
    {
        "rule_id": "oci.compute.audit.launch_instance",
        "service": "compute", "severity": "medium",
        "title": "OCI Compute: Instance Launched",
        "description": "A new compute instance was launched. Unauthorized instance launches may indicate resource hijacking for cryptomining or infrastructure pivoting.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1204"],
        "risk_score": 65,
        "resource": "oci_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "LaunchInstance"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.instance_action",
        "service": "compute", "severity": "medium",
        "title": "OCI Compute: Instance Action Performed (Start/Stop/Reset)",
        "description": "An instance action (START, STOP, RESET, SOFTRESET) was performed. Unauthorized stop/reset actions can cause service disruption.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1529"],
        "risk_score": 62,
        "resource": "oci_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "InstanceAction"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.terminate_instance",
        "service": "compute", "severity": "high",
        "title": "OCI Compute: Instance Terminated",
        "description": "A compute instance was terminated. Mass termination of instances is a destructive impact technique in ransomware or wiperware attacks.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 80,
        "resource": "oci_compute_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "TerminateInstance"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.instance_console_connection",
        "service": "compute", "severity": "critical",
        "title": "OCI Compute: Instance Console Connection Created",
        "description": "An instance console connection (serial console or VNC) was created. Console connections bypass network-level controls and provide direct VM access.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1098"],
        "risk_score": 88,
        "resource": "oci_compute_instance_console_connection",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "CreateInstanceConsoleConnection"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.boot_volume_clone",
        "service": "compute", "severity": "high",
        "title": "OCI Compute: Boot Volume Cloned",
        "description": "A boot volume was cloned. Volume cloning is used by attackers to create exfiltration copies of disk data outside the victim account.",
        "threat_category": "collection",
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1005"],
        "risk_score": 78,
        "resource": "oci_core_boot_volume",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "CreateBootVolumeBackup"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.custom_image_created",
        "service": "compute", "severity": "high",
        "title": "OCI Compute: Custom Image Created",
        "description": "A custom compute image was created from an instance. Attackers create images to persist backdoors that survive instance termination.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1525"],
        "risk_score": 75,
        "resource": "oci_compute_image",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "equals", "value": "CreateImage"},
        ]}},
    },
    {
        "rule_id": "oci.compute.audit.instance_pool_change",
        "service": "compute", "severity": "medium",
        "title": "OCI Compute: Instance Pool Modified",
        "description": "An instance pool was created, updated, or deleted. Unauthorized pool modifications can scale out attacker-controlled compute resources.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1496"],
        "risk_score": 65,
        "resource": "oci_compute_instance_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.computemanagement"},
            {"field": "operation",   "op": "in", "value": ["CreateInstancePool", "UpdateInstancePool", "TerminateInstancePool"]},
        ]}},
    },

    # ── Object Storage ─────────────────────────────────────────────────────
    {
        "rule_id": "oci.objectstorage.audit.bucket_change",
        "service": "objectstorage", "severity": "high",
        "title": "OCI Object Storage: Bucket Configuration Changed",
        "description": "An Object Storage bucket was created, updated, or deleted. Changes to bucket visibility or lifecycle policies may expose data publicly.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 78,
        "resource": "oci_objectstorage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "in", "value": ["CreateBucket", "UpdateBucket", "DeleteBucket"]},
        ]}},
    },
    {
        "rule_id": "oci.objectstorage.audit.bucket_made_public",
        "service": "objectstorage", "severity": "critical",
        "title": "OCI Object Storage: Bucket Made Publicly Accessible",
        "description": "An OCI Object Storage bucket's public access setting was changed to 'ObjectRead' or 'ObjectReadWithoutList'. Public buckets expose all stored objects to the internet.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 97,
        "resource": "oci_objectstorage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "equals", "value": "UpdateBucket"},
            {"field": "request.publicAccessType", "op": "in", "value": ["ObjectRead", "ObjectReadWithoutList"]},
        ]}},
    },
    {
        "rule_id": "oci.objectstorage.audit.bucket_policy_change",
        "service": "objectstorage", "severity": "high",
        "title": "OCI Object Storage: Bucket Policy Changed",
        "description": "The IAM or resource policy on an OCI Object Storage bucket was modified. Policy changes may grant cross-tenancy access to sensitive data.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 82,
        "resource": "oci_objectstorage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "in", "value": ["CreateBucketPolicyStatement", "DeleteBucketPolicyStatement"]},
        ]}},
    },
    {
        "rule_id": "oci.objectstorage.audit.preauthenticated_request_created",
        "service": "objectstorage", "severity": "critical",
        "title": "OCI Object Storage: Pre-Authenticated Request Created",
        "description": "A pre-authenticated request (PAR) was created for an Object Storage bucket or object. PARs allow unauthenticated access to specific resources without OCI credentials.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 90,
        "resource": "oci_objectstorage_preauthenticated_request",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "equals", "value": "CreatePreauthenticatedRequest"},
        ]}},
    },
    {
        "rule_id": "oci.objectstorage.audit.lifecycle_policy_deleted",
        "service": "objectstorage", "severity": "medium",
        "title": "OCI Object Storage: Object Lifecycle Policy Deleted",
        "description": "An object lifecycle policy was deleted from a bucket. Removing lifecycle policies stops automated data retention enforcement.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 58,
        "resource": "oci_objectstorage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "equals", "value": "DeleteObjectLifecyclePolicy"},
        ]}},
    },
    {
        "rule_id": "oci.objectstorage.audit.replication_policy_deleted",
        "service": "objectstorage", "severity": "medium",
        "title": "OCI Object Storage: Replication Policy Deleted",
        "description": "An Object Storage replication policy was deleted. Removing replication can eliminate backup copies needed for disaster recovery.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 65,
        "resource": "oci_objectstorage_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
            {"field": "operation",   "op": "equals", "value": "DeleteReplicationPolicy"},
        ]}},
    },

    # ── Networking / VCN ──────────────────────────────────────────────────
    {
        "rule_id": "oci.networking.audit.vcn_change",
        "service": "networking", "severity": "medium",
        "title": "OCI Networking: VCN Created or Deleted",
        "description": "A Virtual Cloud Network was created or deleted. Unauthorized VCN changes can reshape network topology to enable lateral movement.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1599"],
        "risk_score": 65,
        "resource": "oci_core_vcn",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["CreateVcn", "DeleteVcn"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.security_list_change",
        "service": "networking", "severity": "high",
        "title": "OCI Networking: Security List Rules Modified",
        "description": "VCN security list ingress or egress rules were added, updated, or deleted. Overly permissive rules (0.0.0.0/0) open the environment to external attacks.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1562"],
        "risk_score": 80,
        "resource": "oci_core_security_list",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["CreateSecurityList", "UpdateSecurityList", "DeleteSecurityList"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.nsg_rule_change",
        "service": "networking", "severity": "high",
        "title": "OCI Networking: Network Security Group Rule Modified",
        "description": "A Network Security Group (NSG) rule was added, updated, or removed. NSG rule changes directly affect traffic allowed to or from compute instances.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "oci_core_network_security_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["AddNetworkSecurityGroupSecurityRules", "UpdateNetworkSecurityGroupSecurityRules", "RemoveNetworkSecurityGroupSecurityRules"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.route_table_change",
        "service": "networking", "severity": "high",
        "title": "OCI Networking: Route Table Modified",
        "description": "A VCN route table was created, updated, or deleted. Malicious route table changes can redirect traffic through attacker-controlled gateways.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1557"],
        "risk_score": 80,
        "resource": "oci_core_route_table",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["CreateRouteTable", "UpdateRouteTable", "DeleteRouteTable"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.internet_gateway_change",
        "service": "networking", "severity": "high",
        "title": "OCI Networking: Internet Gateway Created or Deleted",
        "description": "A VCN Internet Gateway was created or deleted. Creating an internet gateway for an internal VCN exposes private resources to the internet.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1562"],
        "risk_score": 85,
        "resource": "oci_core_internet_gateway",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["CreateInternetGateway", "UpdateInternetGateway", "DeleteInternetGateway"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.nat_gateway_change",
        "service": "networking", "severity": "medium",
        "title": "OCI Networking: NAT Gateway Modified",
        "description": "A NAT Gateway was created, updated, or deleted. Deleting NAT gateways breaks outbound internet access for private subnets.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1498"],
        "risk_score": 62,
        "resource": "oci_core_nat_gateway",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.networking"},
            {"field": "operation",   "op": "in", "value": ["CreateNatGateway", "UpdateNatGateway", "DeleteNatGateway"]},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.vcn_flow_ssh_inbound",
        "service": "networking", "severity": "medium",
        "title": "OCI VCN Flow: SSH Traffic Observed (Port 22)",
        "description": "Inbound SSH traffic (port 22) was detected in VCN flow logs. SSH from unexpected sources may indicate brute force or unauthorized remote access.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1021"],
        "risk_score": 65,
        "resource": "oci_core_vcn",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_vcn_flow"},
            {"field": "destination_port", "op": "equals", "value": 22},
            {"field": "direction",        "op": "equals", "value": "INGRESS"},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.vcn_flow_rdp_inbound",
        "service": "networking", "severity": "high",
        "title": "OCI VCN Flow: RDP Traffic Observed (Port 3389)",
        "description": "Inbound RDP traffic (port 3389) was detected. Exposed RDP is a common initial access vector for ransomware groups.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1021"],
        "risk_score": 78,
        "resource": "oci_core_vcn",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_vcn_flow"},
            {"field": "destination_port", "op": "equals", "value": 3389},
            {"field": "direction",        "op": "equals", "value": "INGRESS"},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.vcn_flow_database_port",
        "service": "networking", "severity": "high",
        "title": "OCI VCN Flow: Database Port Exposed to Internet",
        "description": "Database traffic (ports 1521, 3306, 5432, 1433) was observed from an external source. Publicly accessible database ports are a critical risk.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 85,
        "resource": "oci_core_vcn",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",      "op": "equals", "value": "oci_vcn_flow"},
            {"field": "destination_port", "op": "in", "value": [1521, 3306, 5432, 1433]},
            {"field": "direction",        "op": "equals", "value": "INGRESS"},
        ]}},
    },
    {
        "rule_id": "oci.networking.audit.vcn_flow_rejected_traffic",
        "service": "networking", "severity": "low",
        "title": "OCI VCN Flow: High Volume of Rejected Traffic",
        "description": "A high volume of rejected VCN flow log entries was detected, which may indicate a network scan or reconnaissance activity.",
        "threat_category": "discovery",
        "mitre_tactics": ["discovery"],
        "mitre_techniques": ["T1046"],
        "risk_score": 45,
        "resource": "oci_core_vcn",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_vcn_flow"},
            {"field": "action",      "op": "equals", "value": "REJECT"},
        ]}},
    },

    # ── KMS / Vault ────────────────────────────────────────────────────────
    {
        "rule_id": "oci.vault.audit.key_deletion_scheduled",
        "service": "vault", "severity": "critical",
        "title": "OCI Vault: Encryption Key Scheduled for Deletion",
        "description": "An OCI Vault encryption key was scheduled for deletion. Data encrypted with the key will be permanently inaccessible after deletion — a critical impact event.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "risk_score": 98,
        "resource": "oci_kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.vault"},
            {"field": "operation",   "op": "in", "value": ["ScheduleKeyDeletion", "ScheduleKeyVersionDeletion"]},
        ]}},
    },
    {
        "rule_id": "oci.vault.audit.key_disabled",
        "service": "vault", "severity": "high",
        "title": "OCI Vault: Encryption Key Disabled",
        "description": "An OCI Vault key was disabled. Disabling keys used by running services causes decryption failures and may constitute a denial-of-service.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 85,
        "resource": "oci_kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.vault"},
            {"field": "operation",   "op": "equals", "value": "DisableKey"},
        ]}},
    },
    {
        "rule_id": "oci.vault.audit.secret_accessed",
        "service": "vault", "severity": "high",
        "title": "OCI Vault: Secret Version Retrieved",
        "description": "A secret's content was retrieved from OCI Vault. Unusual access patterns may indicate credential theft by a compromised workload or insider threat.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 72,
        "resource": "oci_vault_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.vault"},
            {"field": "operation",   "op": "equals", "value": "GetSecretBundle"},
        ]}},
    },
    {
        "rule_id": "oci.vault.audit.secret_deleted",
        "service": "vault", "severity": "high",
        "title": "OCI Vault: Secret Deleted",
        "description": "A secret was scheduled for deletion or immediately deleted from OCI Vault. Applications depending on the deleted secret will fail to authenticate.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 80,
        "resource": "oci_vault_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.vault"},
            {"field": "operation",   "op": "in", "value": ["ScheduleSecretDeletion", "CancelSecretDeletion"]},
        ]}},
    },

    # ── Database (DB Systems + ATP) ────────────────────────────────────────
    {
        "rule_id": "oci.database.audit.db_system_deleted",
        "service": "database", "severity": "critical",
        "title": "OCI Database: DB System Deleted",
        "description": "An OCI DB System was deleted. Without a recent backup, database deletion results in permanent data loss.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "oci_database_db_system",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.database"},
            {"field": "operation",   "op": "equals", "value": "DeleteDbSystem"},
        ]}},
    },
    {
        "rule_id": "oci.database.audit.atp_wallet_downloaded",
        "service": "database", "severity": "critical",
        "title": "OCI Database: ATP/ADW Connection Wallet Downloaded",
        "description": "An ATP or Autonomous Data Warehouse connection wallet was generated and downloaded. Wallets contain TLS certificates and connection details that allow remote database access.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 88,
        "resource": "oci_database_autonomous_database",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.database"},
            {"field": "operation",   "op": "equals", "value": "GenerateAutonomousDatabaseWallet"},
        ]}},
    },
    {
        "rule_id": "oci.database.audit.db_backup_deleted",
        "service": "database", "severity": "high",
        "title": "OCI Database: DB Backup Deleted",
        "description": "A database backup was deleted. Removing backups leaves the database without recovery options in the event of ransomware or accidental deletion.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "oci_database_backup",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.database"},
            {"field": "operation",   "op": "equals", "value": "DeleteBackup"},
        ]}},
    },
    {
        "rule_id": "oci.database.audit.db_failed_login",
        "service": "database", "severity": "medium",
        "title": "OCI DB Audit: Failed Database Login",
        "description": "Multiple failed login attempts were recorded in OCI Database audit logs, indicating potential brute force activity.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1110"],
        "risk_score": 68,
        "resource": "oci_database_db_system",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_db_audit"},
            {"field": "db_action",   "op": "equals", "value": "LOGON"},
            {"field": "return_code", "op": "not_equals", "value": 0},
        ]}},
    },
    {
        "rule_id": "oci.database.audit.admin_activity",
        "service": "database", "severity": "high",
        "title": "OCI DB Audit: Privileged Admin Activity",
        "description": "DBA or SYSDBA-privileged activity was recorded in database audit logs. Unauthorized admin actions can modify schema, bypass row security, or exfiltrate data.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1078"],
        "risk_score": 80,
        "resource": "oci_database_db_system",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",   "op": "equals", "value": "oci_db_audit"},
            {"field": "privilege_used","op": "in", "value": ["SYSDBA", "SYSOPER", "DBA"]},
        ]}},
    },
    {
        "rule_id": "oci.database.audit.ddl_table_change",
        "service": "database", "severity": "high",
        "title": "OCI DB Audit: DDL Table Change (DROP/ALTER)",
        "description": "A DDL statement (DROP TABLE, ALTER TABLE, TRUNCATE) was executed. Unauthorized DDL changes can destroy data or modify schema to bypass security controls.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 82,
        "resource": "oci_database_db_system",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_db_audit"},
            {"field": "action_name", "op": "in", "value": ["DROP TABLE", "ALTER TABLE", "TRUNCATE TABLE"]},
        ]}},
    },

    # ── Logging / Audit ────────────────────────────────────────────────────
    {
        "rule_id": "oci.logging.audit.audit_config_change",
        "service": "logging", "severity": "critical",
        "title": "OCI Logging: Audit Configuration Changed",
        "description": "The OCI Audit service configuration was modified. Disabling or restricting audit logging removes visibility into tenant activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 93,
        "resource": "oci_audit_configuration",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.audit"},
            {"field": "operation",   "op": "equals", "value": "UpdateConfiguration"},
        ]}},
    },
    {
        "rule_id": "oci.logging.audit.log_group_deleted",
        "service": "logging", "severity": "high",
        "title": "OCI Logging: Log Group Deleted",
        "description": "An OCI Logging log group was deleted. Deleting log groups stops collection of audit and service logs from associated resources.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 82,
        "resource": "oci_logging_log_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.logging"},
            {"field": "operation",   "op": "equals", "value": "DeleteLogGroup"},
        ]}},
    },
    {
        "rule_id": "oci.logging.audit.log_service_disabled",
        "service": "logging", "severity": "high",
        "title": "OCI Logging: Service Log Disabled",
        "description": "A service log (VCN flow, load balancer, Object Storage, etc.) was disabled. Disabling service logs removes audit trails for specific services.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "oci_logging_log",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.logging"},
            {"field": "operation",   "op": "equals", "value": "UpdateLog"},
            {"field": "request.updateLogDetails.isEnabled", "op": "equals", "value": False},
        ]}},
    },

    # ── Cloud Guard ────────────────────────────────────────────────────────
    {
        "rule_id": "oci.cloudguard.audit.cloud_guard_disabled",
        "service": "cloudguard", "severity": "critical",
        "title": "OCI Cloud Guard: Cloud Guard Disabled",
        "description": "Oracle Cloud Guard was disabled for the tenancy. Cloud Guard is the primary threat detection service in OCI; disabling it blinds the security team.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 97,
        "resource": "oci_cloud_guard_configuration",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.cloudguard"},
            {"field": "operation",   "op": "equals", "value": "UpdateConfiguration"},
            {"field": "request.status", "op": "equals", "value": "DISABLED"},
        ]}},
    },
    {
        "rule_id": "oci.cloudguard.audit.critical_problem",
        "service": "cloudguard", "severity": "critical",
        "title": "OCI Cloud Guard: Critical Problem Detected",
        "description": "Cloud Guard detected a critical-severity security problem. Critical problems indicate active threats or severe misconfigurations requiring immediate remediation.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 95,
        "resource": "oci_cloud_guard_problem",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_cloudguard"},
            {"field": "risk_level",  "op": "equals", "value": "CRITICAL"},
        ]}},
    },
    {
        "rule_id": "oci.cloudguard.audit.detector_recipe_change",
        "service": "cloudguard", "severity": "high",
        "title": "OCI Cloud Guard: Detector Recipe Modified",
        "description": "A Cloud Guard detector recipe was modified. Attackers may disable specific detectors to blind detection for their specific attack techniques.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 85,
        "resource": "oci_cloud_guard_detector_recipe",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_cloudguard"},
            {"field": "event_type",  "op": "equals", "value": "DETECTOR_RECIPE_CHANGED"},
        ]}},
    },
    {
        "rule_id": "oci.cloudguard.audit.security_zone_violation",
        "service": "cloudguard", "severity": "high",
        "title": "OCI Cloud Guard: Security Zone Policy Violation",
        "description": "A Cloud Guard Security Zone policy violation was detected. Security Zones enforce mandatory security policies; violations indicate a deliberate policy bypass attempt.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 82,
        "resource": "oci_cloud_guard_security_zone",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_cloudguard"},
            {"field": "event_type",  "op": "equals", "value": "SECURITY_ZONE_VIOLATION"},
        ]}},
    },

    # ── OKE (Oracle Container Engine) ──────────────────────────────────────
    {
        "rule_id": "oci.oke.audit.cluster_deleted",
        "service": "oke", "severity": "critical",
        "title": "OCI OKE: Kubernetes Cluster Deleted",
        "description": "An OKE cluster was deleted. Cluster deletion terminates all workloads and is a destructive impact action.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "oci_containerengine_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.containerengine"},
            {"field": "operation",   "op": "equals", "value": "DeleteCluster"},
        ]}},
    },
    {
        "rule_id": "oci.oke.audit.node_pool_deleted",
        "service": "oke", "severity": "high",
        "title": "OCI OKE: Node Pool Deleted",
        "description": "An OKE node pool was deleted, terminating all worker nodes in the pool and evicting running workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "oci_containerengine_node_pool",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.containerengine"},
            {"field": "operation",   "op": "equals", "value": "DeleteNodePool"},
        ]}},
    },
    {
        "rule_id": "oci.oke.audit.privileged_pod",
        "service": "oke", "severity": "critical",
        "title": "OCI OKE: Privileged Pod Created",
        "description": "A privileged Kubernetes pod was created in an OKE cluster. Privileged pods have host-level access and can be used for container escapes.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 92,
        "resource": "oci_containerengine_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_k8s_audit"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "request.spec.containers.securityContext.privileged", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "oci.oke.audit.pod_exec",
        "service": "oke", "severity": "high",
        "title": "OCI OKE: kubectl exec / attach into Pod",
        "description": "An interactive exec or attach session was opened into a running pod. Exec sessions are commonly used for reconnaissance and lateral movement within clusters.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 80,
        "resource": "oci_containerengine_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "in", "value": ["exec", "attach"]},
        ]}},
    },
    {
        "rule_id": "oci.oke.audit.rolebinding_change",
        "service": "oke", "severity": "critical",
        "title": "OCI OKE: RBAC RoleBinding Created or Modified",
        "description": "A Kubernetes RoleBinding or ClusterRoleBinding was created or modified in an OKE cluster. Unauthorized bindings grant attackers persistent access to cluster resources.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 90,
        "resource": "oci_containerengine_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_k8s_audit"},
            {"field": "resource",    "op": "in", "value": ["rolebindings", "clusterrolebindings"]},
            {"field": "verb",        "op": "in", "value": ["create", "update", "patch"]},
        ]}},
    },
    {
        "rule_id": "oci.oke.audit.secret_read",
        "service": "oke", "severity": "high",
        "title": "OCI OKE: Kubernetes Secret Accessed",
        "description": "A Kubernetes Secret was read in an OKE cluster. Secrets contain credentials; unauthorized reads indicate credential harvesting.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 78,
        "resource": "oci_containerengine_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "in", "value": ["get", "list", "watch"]},
        ]}},
    },

    # ── WAF ────────────────────────────────────────────────────────────────
    {
        "rule_id": "oci.waf.audit.sql_injection",
        "service": "waf", "severity": "critical",
        "title": "OCI WAF: SQL Injection Attack Detected",
        "description": "OCI Web Application Firewall detected a SQL injection attack. Successful SQL injection can lead to unauthorized data access or database manipulation.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 95,
        "resource": "oci_waf_web_app_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",     "op": "equals", "value": "oci_waf"},
            {"field": "threat_category", "op": "equals", "value": "SQL_INJECTION"},
        ]}},
    },
    {
        "rule_id": "oci.waf.audit.xss_detected",
        "service": "waf", "severity": "high",
        "title": "OCI WAF: Cross-Site Scripting (XSS) Detected",
        "description": "OCI WAF detected an XSS attack attempt. XSS attacks can steal session tokens and hijack user sessions.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1059"],
        "risk_score": 80,
        "resource": "oci_waf_web_app_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",     "op": "equals", "value": "oci_waf"},
            {"field": "threat_category", "op": "equals", "value": "XSS"},
        ]}},
    },
    {
        "rule_id": "oci.waf.audit.rate_limit_triggered",
        "service": "waf", "severity": "medium",
        "title": "OCI WAF: Rate Limit Rule Triggered",
        "description": "A WAF rate limiting rule was triggered, indicating high-volume requests from a single source. This may indicate a DoS attempt or automated scanner.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1498"],
        "risk_score": 62,
        "resource": "oci_waf_web_app_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "oci_waf"},
            {"field": "action_taken", "op": "equals", "value": "RATE_LIMIT"},
        ]}},
    },
    {
        "rule_id": "oci.waf.audit.bot_detected",
        "service": "waf", "severity": "medium",
        "title": "OCI WAF: Bot Traffic Detected",
        "description": "OCI WAF detected bot traffic. Malicious bots can be used for credential stuffing, scraping, or DDoS amplification.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1078"],
        "risk_score": 58,
        "resource": "oci_waf_web_app_firewall",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "oci_waf"},
            {"field": "action_taken", "op": "in", "value": ["BOT_MANAGEMENT", "BLOCK"]},
        ]}},
    },

    # ── Compartment / Resource Manager ────────────────────────────────────
    {
        "rule_id": "oci.resourcemanager.audit.compartment_change",
        "service": "resourcemanager", "severity": "high",
        "title": "OCI Tenancy: Compartment Created, Deleted, or Moved",
        "description": "An OCI compartment was created, deleted, or moved. Compartments are the primary access control boundary in OCI; unauthorized changes can expose resources.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "oci_identity_compartment",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
            {"field": "operation",   "op": "in", "value": ["CreateCompartment", "DeleteCompartment", "MoveCompartment"]},
        ]}},
    },
    {
        "rule_id": "oci.resourcemanager.audit.stack_applied",
        "service": "resourcemanager", "severity": "medium",
        "title": "OCI Resource Manager: Terraform Stack Applied",
        "description": "An OCI Resource Manager (Terraform) stack was applied. Unauthorized stack apply operations can create, modify, or delete any OCI resources.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1059"],
        "risk_score": 70,
        "resource": "oci_resource_manager_stack",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "oci_audit"},
            {"field": "service",     "op": "equals", "value": "com.oraclecloud.resourcemanager"},
            {"field": "operation",   "op": "in", "value": ["CreateJob", "UpdateJob"]},
            {"field": "request.operation", "op": "equals", "value": "APPLY"},
        ]}},
    },

    # ── CIEM Correlation Chains ────────────────────────────────────────────
    {
        "rule_id": "oci.ciem.chain.privilege_escalation_via_policy",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "OCI CIEM: Privilege Escalation via Policy Creation + API Key",
        "description": "Detect the OCI privilege escalation chain: IAM policy created with broad permissions → new API key created → privileged API calls, indicating a multi-step takeover.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 98,
        "resource": "oci_identity_policy",
        "check_config": {
            "type": "sequence",
            "window_seconds": 600,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
                    {"field": "operation",   "op": "in", "value": ["CreatePolicy", "UpdatePolicy"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.identitycontrolplane"},
                    {"field": "operation",   "op": "in", "value": ["UploadApiKey", "CreateAuthToken"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "oci.ciem.chain.data_exfiltration_via_par",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "OCI CIEM: Data Exfiltration via Bucket Public Access + PAR Creation",
        "description": "Detect a data exfiltration pattern: bucket made public or PAR created → large object download activity, indicating exfiltration of Object Storage data.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 97,
        "resource": "oci_objectstorage_bucket",
        "check_config": {
            "type": "sequence",
            "window_seconds": 900,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
                    {"field": "operation",   "op": "in", "value": ["UpdateBucket", "CreatePreauthenticatedRequest"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.objectstorage"},
                    {"field": "operation",   "op": "in", "value": ["GetObject", "ListObjects"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "oci.ciem.chain.defense_evasion_log_destroy",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "OCI CIEM: Defense Evasion via Log Group Deletion + Cloud Guard Disable",
        "description": "Detect an evidence destruction chain: log group deleted + Cloud Guard disabled within a short window, indicating an attacker eliminating detection capabilities.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 99,
        "resource": "oci_logging_log_group",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.logging"},
                    {"field": "operation",   "op": "equals", "value": "DeleteLogGroup"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "oci_audit"},
                    {"field": "service",     "op": "equals", "value": "com.oraclecloud.cloudguard"},
                    {"field": "operation",   "op": "equals", "value": "UpdateConfiguration"},
                ]}},
            ],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Generator helpers (same pattern as GCP/K8s generators)
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    if any(c in value for c in (": ", "#", "'", '"', "\n", "{")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_value(v: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(v, dict):
        lines = ["{"]
        for dk, dv in v.items():
            lines.append(f"{pad}  {dk}: {_dump_value(dv, indent + 1)}")
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    if isinstance(v, list):
        if all(isinstance(i, (str, int, float, bool)) for i in v):
            return "[" + ", ".join(json.dumps(i) for i in v) + "]"
        lines = []
        for item in v:
            lines.append(f"{pad}- {_dump_value(item, indent + 1)}")
        return "\n" + "\n".join(lines)
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    return _yaml_str(str(v))


def _conditions_to_yaml(cond: dict, indent: int = 0) -> list[str]:
    lines: list[str] = []
    pad = "  " * indent
    if "type" in cond:  # correlation config
        lines.append(f"{pad}type: {cond['type']}")
        if "window_seconds" in cond:
            lines.append(f"{pad}window_seconds: {cond['window_seconds']}")
        if "events" in cond:
            lines.append(f"{pad}events:")
            for ev in cond["events"]:
                lines.append(f"{pad}- conditions:")
                for sub in _conditions_to_yaml(ev["conditions"], indent + 2):
                    lines.append(sub)
        return lines
    for key, items in cond.items():
        lines.append(f"{pad}{key}:")
        for item in items:
            field = item["field"]
            op = item["op"]
            val = item["value"]
            lines.append(f"{pad}- field: {_yaml_str(field)}")
            lines.append(f"{pad}  op: {op}")
            lines.append(f"{pad}  value: {_dump_value(val)}")
    return lines


def generate_yaml(rule: dict) -> str:
    rid = rule["rule_id"]
    svc = rule.get("service", rid.split(".")[1])
    check_type = rule.get("check_type", "log")
    tactics_str = "[" + ", ".join(rule.get("mitre_tactics", [])) + "]"
    techniques_str = "[" + ", ".join(rule.get("mitre_techniques", [])) + "]"
    frameworks = '["SOC2", "ISO27001"]'
    check_config = rule.get("check_config", {})

    lines: list[str] = [
        f"rule_id: {rid}",
        f"provider: oci",
        f"service: {svc}",
        f"resource: {rule.get('resource', '')}",
        f"check_type: {check_type}",
        f"severity: {rule['severity']}",
        f"risk_score: {rule.get('risk_score', 50)}",
        f"title: {_yaml_str(rule['title'])}",
        f"description: {_yaml_str(rule['description'])}",
        f"threat_category: {rule.get('threat_category', '')}",
        f"mitre_tactics: {tactics_str}",
        f"mitre_techniques: {techniques_str}",
        "compliance_frameworks: {}",
        "remediation: Review and investigate this activity in the OCI Console and take corrective action.",
        "check_config:",
    ]

    if "type" in check_config:  # correlation
        for sub in _conditions_to_yaml(check_config, indent=1):
            lines.append(sub)
    else:
        lines.append("  conditions:")
        for sub in _conditions_to_yaml(check_config.get("conditions", {}), indent=2):
            lines.append(sub)

    return "\n".join(lines) + "\n"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for rule in RULES:
        rid = rule["rule_id"]
        parts = rid.split(".")
        svc = parts[1] if len(parts) > 1 else "general"
        svc_dir = OUT_DIR / svc
        svc_dir.mkdir(exist_ok=True)
        path = svc_dir / f"{rid}.yaml"
        path.write_text(generate_yaml(rule))
        counts[svc] = counts.get(svc, 0) + 1

    total = sum(counts.values())
    for svc, n in sorted(counts.items()):
        print(f"  {svc:<25} {n:3d} rules")
    print(f"Generated : {total}")


if __name__ == "__main__":
    main()
