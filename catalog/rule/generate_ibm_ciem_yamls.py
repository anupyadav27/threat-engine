#!/usr/bin/env python3
"""
generate_ibm_ciem_yamls.py — Generate IBM Cloud CIEM log-detection rule YAMLs.

Output: catalog/rule/ibm_rule_ciem/<service>/<rule_id>.yaml
Run:    python3 catalog/rule/generate_ibm_ciem_yamls.py

IBM Cloud source_types:
  ibm_activity  — IBM Cloud Activity Tracker (all control-plane events)
  ibm_k8s_audit — IBM Kubernetes Service (IKS) cluster audit logs
  ibm_db_audit  — IBM Db2/PostgreSQL audit logs
  ibm_scc       — IBM Security and Compliance Center findings
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_DIR = ROOT / "catalog" / "rule" / "ibm_rule_ciem"

# IBM Activity Tracker uses dot-separated operation format:
#   <service-name>.<resource-type>.<action>
# Examples:
#   iam-identity.user-apikey.create
#   cloud-object-storage.bucket.create
#   containers-kubernetes.cluster.delete
#   kms.secrets.delete
#   databases-for-postgresql.instance.delete

RULES: list[dict[str, Any]] = [

    # ── IAM / Identity ────────────────────────────────────────────────────
    {
        "rule_id": "ibm.iam.activity.api_key_created",
        "service": "iam", "severity": "high",
        "title": "IBM IAM: API Key Created",
        "description": "An IBM Cloud API key was created for a user or service ID. API keys are long-lived credentials that provide programmatic access to all IBM Cloud services the identity has access to.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 78,
        "resource": "ibm_iam_api_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["iam-identity.user-apikey.create", "iam-identity.serviceid-apikey.create"]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.api_key_deleted",
        "service": "iam", "severity": "medium",
        "title": "IBM IAM: API Key Deleted",
        "description": "An IBM Cloud API key was deleted. Attackers may delete keys to cover tracks after rotating to newly created credentials.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1070"],
        "risk_score": 60,
        "resource": "ibm_iam_api_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["iam-identity.user-apikey.delete", "iam-identity.serviceid-apikey.delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.service_id_created",
        "service": "iam", "severity": "high",
        "title": "IBM IAM: Service ID Created",
        "description": "A new IBM Cloud Service ID was created. Service IDs can be assigned policies to access IBM Cloud services programmatically and should be monitored for unauthorized creation.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136"],
        "risk_score": 74,
        "resource": "ibm_iam_service_id",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "iam-identity.serviceid.create"},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.service_id_locked",
        "service": "iam", "severity": "high",
        "title": "IBM IAM: Service ID Locked or Unlocked",
        "description": "An IBM Cloud Service ID was locked or unlocked. Unlocking a service ID that was locked for security reasons re-enables compromised credentials.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 72,
        "resource": "ibm_iam_service_id",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["iam-identity.serviceid.lock", "iam-identity.serviceid.unlock"]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.policy_created",
        "service": "iam", "severity": "critical",
        "title": "IBM IAM: IAM Policy Created",
        "description": "A new IAM access policy was created. Policies granting Administrator or Editor roles on sensitive services or all resources enable privilege escalation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 88,
        "resource": "ibm_iam_access_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "iam-am.policy.create"},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.policy_change",
        "service": "iam", "severity": "critical",
        "title": "IBM IAM: IAM Policy Modified",
        "description": "An IAM access policy was updated. Policy modifications expanding roles (Reader → Administrator) on critical services constitute privilege escalation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 90,
        "resource": "ibm_iam_access_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["iam-am.policy.update", "iam-am.policy.delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.access_group_change",
        "service": "iam", "severity": "high",
        "title": "IBM IAM: Access Group Modified",
        "description": "An IAM access group was created, modified, or a member was added. Access groups aggregate policies; unauthorized additions grant attackers all group permissions.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098"],
        "risk_score": 82,
        "resource": "ibm_iam_access_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "iam-groups.group.create",
                "iam-groups.group.update",
                "iam-groups.group.delete",
                "iam-groups.members.add",
                "iam-groups.members.delete",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.mfa_settings_change",
        "service": "iam", "severity": "critical",
        "title": "IBM IAM: MFA Settings Changed",
        "description": "Multi-factor authentication settings were modified for the IBM Cloud account. Disabling MFA removes a critical account takeover protection.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1556"],
        "risk_score": 93,
        "resource": "ibm_iam_settings",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["iam-identity.accountsettings.update", "iam-identity.mfaenrollment.update"]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.trusted_profile_change",
        "service": "iam", "severity": "critical",
        "title": "IBM IAM: Trusted Profile Modified",
        "description": "An IBM Cloud Trusted Profile was created, updated, or had a claim rule modified. Trusted profiles allow compute resources or federated users to assume IBM Cloud identities without API keys.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "initial_access"],
        "mitre_techniques": ["T1078"],
        "risk_score": 90,
        "resource": "ibm_iam_trusted_profile",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "iam-identity.profile.create",
                "iam-identity.profile.update",
                "iam-identity.profile.delete",
                "iam-identity.profile-claimrule.create",
                "iam-identity.profile-claimrule.update",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.iam.activity.account_settings_change",
        "service": "iam", "severity": "high",
        "title": "IBM IAM: Account Settings Changed",
        "description": "Global IBM Cloud account security settings were changed (e.g., restrict API key creation, session timeout, IP address restrictions).",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 80,
        "resource": "ibm_iam_settings",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "iam-identity.accountsettings.update"},
        ]}},
    },

    # ── Cloud Object Storage (COS) ────────────────────────────────────────
    {
        "rule_id": "ibm.cos.activity.bucket_created_public",
        "service": "cos", "severity": "critical",
        "title": "IBM COS: Object Storage Bucket Created with Public Access",
        "description": "An IBM Cloud Object Storage bucket was created with public access enabled. Public buckets expose all stored objects to the internet.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 97,
        "resource": "ibm_cos_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "cloud-object-storage.bucket.create"},
            {"field": "request.publicAccess", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "ibm.cos.activity.bucket_change",
        "service": "cos", "severity": "high",
        "title": "IBM COS: Object Storage Bucket Configuration Changed",
        "description": "An Object Storage bucket ACL or configuration was modified. Changes may expose data publicly or remove encryption/versioning protections.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 78,
        "resource": "ibm_cos_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "cloud-object-storage.bucket.update",
                "cloud-object-storage.bucket-acl.update",
                "cloud-object-storage.bucket-cors.update",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.cos.activity.bucket_policy_change",
        "service": "cos", "severity": "high",
        "title": "IBM COS: Object Storage Bucket Policy Changed",
        "description": "An Object Storage bucket IAM policy was modified. Policy changes may grant cross-account access to sensitive data.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 82,
        "resource": "ibm_cos_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["cloud-object-storage.bucket-policy.create", "cloud-object-storage.bucket-policy.update", "cloud-object-storage.bucket-policy.delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.cos.activity.hmac_key_created",
        "service": "cos", "severity": "high",
        "title": "IBM COS: HMAC Key Created for Service Credential",
        "description": "An HMAC key was created for IBM COS S3-compatible access. HMAC keys are long-lived credentials that can be exported and used to access all objects in authorized buckets.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 76,
        "resource": "ibm_cos_credential",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "cloud-object-storage.credential.create"},
            {"field": "request.role", "op": "equals", "value": "Writer"},
        ]}},
    },
    {
        "rule_id": "ibm.cos.activity.bucket_deleted",
        "service": "cos", "severity": "high",
        "title": "IBM COS: Object Storage Bucket Deleted",
        "description": "An IBM COS bucket was deleted. Bucket deletion is irreversible and results in permanent data loss for all stored objects.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "ibm_cos_bucket",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "cloud-object-storage.bucket.delete"},
        ]}},
    },

    # ── VPC / Networking ──────────────────────────────────────────────────
    {
        "rule_id": "ibm.vpc.activity.security_group_rule_change",
        "service": "vpc", "severity": "high",
        "title": "IBM VPC: Security Group Rule Modified",
        "description": "A VPC security group rule was added, updated, or deleted. Overly permissive rules (0.0.0.0/0 inbound) open compute resources to external attacks.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "initial_access"],
        "mitre_techniques": ["T1562"],
        "risk_score": 80,
        "resource": "ibm_is_security_group",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "is.security-group.security-group-rule.create",
                "is.security-group.security-group-rule.update",
                "is.security-group.security-group-rule.delete",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.vpc.activity.vpc_change",
        "service": "vpc", "severity": "medium",
        "title": "IBM VPC: VPC Created or Deleted",
        "description": "An IBM VPC was created or deleted. Unauthorized VPC changes reshape network topology and may expose private resources.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1599"],
        "risk_score": 65,
        "resource": "ibm_is_vpc",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["is.vpc.vpc.create", "is.vpc.vpc.delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.vpc.activity.public_gateway_change",
        "service": "vpc", "severity": "high",
        "title": "IBM VPC: Public Gateway Created or Deleted",
        "description": "A VPC public gateway was created or deleted. Creating a public gateway exposes private subnet resources to the internet; deleting one breaks outbound connectivity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "ibm_is_public_gateway",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["is.public-gateway.public-gateway.create", "is.public-gateway.public-gateway.delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.vpc.activity.floating_ip_change",
        "service": "vpc", "severity": "medium",
        "title": "IBM VPC: Floating IP Address Assigned",
        "description": "A floating (public) IP was associated with a compute instance. Public IPs expose instances to direct internet access.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 65,
        "resource": "ibm_is_floating_ip",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["is.floating-ip.floating-ip.create", "is.instance.instance.update"]},
        ]}},
    },
    {
        "rule_id": "ibm.vpc.activity.network_acl_change",
        "service": "vpc", "severity": "high",
        "title": "IBM VPC: Network ACL Modified",
        "description": "A VPC network ACL rule was modified. Network ACLs control subnet-level traffic; permissive changes affect all instances in a subnet.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 76,
        "resource": "ibm_is_network_acl",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["is.network-acl.network-acl-rule.create", "is.network-acl.network-acl-rule.update", "is.network-acl.network-acl-rule.delete"]},
        ]}},
    },

    # ── Virtual Servers (VSI) ─────────────────────────────────────────────
    {
        "rule_id": "ibm.vsi.activity.vsi_created",
        "service": "vsi", "severity": "medium",
        "title": "IBM VPC: Virtual Server Instance Created",
        "description": "A new virtual server instance was provisioned in IBM VPC. Unauthorized instance creation may indicate resource hijacking for cryptomining.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1204"],
        "risk_score": 65,
        "resource": "ibm_is_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "is.instance.instance.create"},
        ]}},
    },
    {
        "rule_id": "ibm.vsi.activity.vsi_deleted",
        "service": "vsi", "severity": "high",
        "title": "IBM VPC: Virtual Server Instance Deleted",
        "description": "A virtual server instance was deleted. Mass instance deletion is a destructive impact technique.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 78,
        "resource": "ibm_is_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "is.instance.instance.delete"},
        ]}},
    },
    {
        "rule_id": "ibm.vsi.activity.vsi_action",
        "service": "vsi", "severity": "medium",
        "title": "IBM VPC: Virtual Server Action Performed (Start/Stop/Reboot)",
        "description": "A start, stop, reboot, or reset action was performed on a virtual server. Unauthorized stop/reboot disrupts running workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1529"],
        "risk_score": 62,
        "resource": "ibm_is_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["is.instance.instance-action.create"]},
        ]}},
    },
    {
        "rule_id": "ibm.vsi.activity.bare_metal_change",
        "service": "vsi", "severity": "high",
        "title": "IBM: Bare Metal Server Modified or Deleted",
        "description": "An IBM Cloud bare metal server was modified, stopped, or deleted. Bare metal servers host critical workloads and are hard to replace quickly.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 80,
        "resource": "ibm_is_bare_metal_server",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "is.bare-metal-server.bare-metal-server.delete",
                "is.bare-metal-server.bare-metal-server.stop",
            ]},
        ]}},
    },

    # ── Key Protect / Secrets Manager ─────────────────────────────────────
    {
        "rule_id": "ibm.kms.activity.key_protect_key_delete",
        "service": "kms", "severity": "critical",
        "title": "IBM Key Protect: Encryption Key Deleted",
        "description": "An IBM Key Protect encryption key was deleted. Data encrypted with this key is permanently inaccessible after deletion — a critical impact event.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "risk_score": 98,
        "resource": "ibm_kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["kms.secrets.delete", "kms.secrets.setkeyfordeletion"]},
        ]}},
    },
    {
        "rule_id": "ibm.kms.activity.key_protect_key_disable",
        "service": "kms", "severity": "high",
        "title": "IBM Key Protect: Encryption Key Disabled",
        "description": "An IBM Key Protect key was disabled. Disabling keys causes decryption failures for services relying on the key, potentially causing outages.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 85,
        "resource": "ibm_kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "kms.secrets.disable"},
        ]}},
    },
    {
        "rule_id": "ibm.kms.activity.key_protect_key_accessed",
        "service": "kms", "severity": "high",
        "title": "IBM Key Protect: Key Material Accessed",
        "description": "An IBM Key Protect key was used to wrap or unwrap data. Unexpected decrypt operations may indicate unauthorized data access.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 72,
        "resource": "ibm_kms_key",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["kms.secrets.unwrap", "kms.secrets.rewrap"]},
        ]}},
    },
    {
        "rule_id": "ibm.secrets.activity.secrets_manager_change",
        "service": "secrets", "severity": "high",
        "title": "IBM Secrets Manager: Secret Deleted or Modified",
        "description": "An IBM Secrets Manager secret was deleted, rotated, or had its access policy modified. Secret deletion causes authentication failures for dependent applications.",
        "threat_category": "impact",
        "mitre_tactics": ["impact", "credential_access"],
        "mitre_techniques": ["T1531"],
        "risk_score": 80,
        "resource": "ibm_secrets_manager_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["secrets-manager.secret.delete", "secrets-manager.secret-metadata.update"]},
        ]}},
    },

    # ── Kubernetes Service (IKS) ──────────────────────────────────────────
    {
        "rule_id": "ibm.iks.activity.cluster_deleted",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: Kubernetes Cluster Deleted",
        "description": "An IBM Kubernetes Service cluster was deleted. Cluster deletion terminates all workloads and is an irreversible destructive action.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "equals", "value": "containers-kubernetes.cluster.delete"},
        ]}},
    },
    {
        "rule_id": "ibm.iks.activity.cluster_config_update",
        "service": "iks", "severity": "high",
        "title": "IBM IKS: Cluster Configuration Updated",
        "description": "An IKS cluster configuration was updated (e.g., public endpoint enabled, audit log config changed). Security-weakening config changes expand the attack surface.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 78,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "containers-kubernetes.cluster.update",
                "containers-kubernetes.cluster-audit.update",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.privileged_pod",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: Privileged Pod Created",
        "description": "A privileged Kubernetes pod was created in an IKS cluster. Privileged pods have host-level access and can be used for container escapes.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 93,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "request.spec.containers.securityContext.privileged", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.pod_exec",
        "service": "iks", "severity": "high",
        "title": "IBM IKS: kubectl exec / attach into Pod",
        "description": "An interactive exec or attach session was opened into a running pod in an IKS cluster. Used for post-exploitation reconnaissance.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 80,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "in", "value": ["exec", "attach"]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.rolebinding_change",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: RBAC RoleBinding Created or Modified",
        "description": "A Kubernetes RBAC RoleBinding or ClusterRoleBinding was created or modified. Unauthorized bindings grant persistent access to cluster resources.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 90,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "in", "value": ["rolebindings", "clusterrolebindings"]},
            {"field": "verb",        "op": "in", "value": ["create", "update", "patch"]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.secret_accessed",
        "service": "iks", "severity": "high",
        "title": "IBM IKS: Kubernetes Secret Accessed",
        "description": "A Kubernetes Secret was accessed (get/list/watch) in an IKS cluster. Secrets contain credentials and API tokens; unauthorized reads indicate harvesting.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552"],
        "risk_score": 78,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "in", "value": ["get", "list", "watch"]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.secret_modified",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: Kubernetes Secret Modified",
        "description": "A Kubernetes Secret was created, updated, or patched in an IKS cluster. Attackers modify secrets to inject backdoor credentials or hijack service account tokens.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1098"],
        "risk_score": 90,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "in", "value": ["create", "update", "patch", "delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.namespace_change",
        "service": "iks", "severity": "medium",
        "title": "IBM IKS: Namespace Created or Deleted",
        "description": "A Kubernetes namespace was created or deleted. Attackers create namespaces to deploy malicious workloads in isolated contexts that bypass monitoring.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1036"],
        "risk_score": 65,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "namespaces"},
            {"field": "verb",        "op": "in", "value": ["create", "delete"]},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.daemonset_created",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: DaemonSet Created",
        "description": "A Kubernetes DaemonSet was created in an IKS cluster. DaemonSets run on all nodes and are used by attackers to deploy malware with cluster-wide persistence.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1610"],
        "risk_score": 88,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "daemonsets"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.role_deleted",
        "service": "iks", "severity": "high",
        "title": "IBM IKS: RBAC Role or ClusterRole Deleted",
        "description": "A RBAC Role or ClusterRole was deleted from an IKS cluster. Deletion of built-in roles disrupts legitimate access and may be evidence of sabotage.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1531"],
        "risk_score": 78,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "in", "value": ["roles", "clusterroles"]},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "ibm.iks.k8s_audit.webhook_change",
        "service": "iks", "severity": "critical",
        "title": "IBM IKS: Admission Webhook Modified",
        "description": "A Kubernetes ValidatingWebhookConfiguration or MutatingWebhookConfiguration was modified in an IKS cluster. Malicious webhooks can intercept or modify all API server requests.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1505"],
        "risk_score": 93,
        "resource": "ibm_container_cluster",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_k8s_audit"},
            {"field": "resource",    "op": "in", "value": ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]},
            {"field": "verb",        "op": "in", "value": ["create", "update", "patch", "delete"]},
        ]}},
    },

    # ── Activity Tracker / Logging ────────────────────────────────────────
    {
        "rule_id": "ibm.logging.activity.activity_tracker_delete",
        "service": "logging", "severity": "critical",
        "title": "IBM Logging: Activity Tracker Instance Deleted",
        "description": "An IBM Cloud Activity Tracker instance was deleted. Activity Tracker is the primary audit logging service; its deletion removes visibility into all account activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 97,
        "resource": "ibm_logdna_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "logdnaat.instance.delete",
                "atracker.target.delete",
                "atracker.route.delete",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.logging.activity.log_routing_changed",
        "service": "logging", "severity": "high",
        "title": "IBM Logging: Activity Tracker Route or Target Changed",
        "description": "An Activity Tracker routing rule or target was modified. Changing log routes may stop forwarding audit logs to your SIEM, blinding threat detection.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 85,
        "resource": "ibm_atracker_route",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": ["atracker.route.update", "atracker.target.update", "atracker.route.create", "atracker.target.create"]},
        ]}},
    },

    # ── Security and Compliance Center (SCC) ─────────────────────────────
    {
        "rule_id": "ibm.scc.audit.critical_finding",
        "service": "scc", "severity": "critical",
        "title": "IBM SCC: Critical Security Finding Detected",
        "description": "IBM Security and Compliance Center detected a critical-severity finding. Critical findings indicate active threats or critical misconfigurations.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 95,
        "resource": "ibm_scc_finding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "severity",     "op": "equals", "value": "CRITICAL"},
        ]}},
    },
    {
        "rule_id": "ibm.scc.audit.high_finding",
        "service": "scc", "severity": "high",
        "title": "IBM SCC: High-Severity Security Finding",
        "description": "IBM SCC detected a high-severity security finding requiring investigation.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 78,
        "resource": "ibm_scc_finding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "severity",     "op": "equals", "value": "HIGH"},
        ]}},
    },
    {
        "rule_id": "ibm.scc.audit.compliance_violation",
        "service": "scc", "severity": "high",
        "title": "IBM SCC: Compliance Profile Violation",
        "description": "A compliance profile control failure was reported by IBM SCC. Control failures represent persistent misconfigurations against frameworks such as CIS IBM Cloud Foundations.",
        "threat_category": "initial_access",
        "mitre_tactics": ["initial_access"],
        "mitre_techniques": ["T1190"],
        "risk_score": 72,
        "resource": "ibm_scc_profile",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "event_type",   "op": "equals", "value": "COMPLIANCE_VIOLATION"},
        ]}},
    },
    {
        "rule_id": "ibm.scc.audit.policy_violation",
        "service": "scc", "severity": "high",
        "title": "IBM SCC: Security Policy Violation",
        "description": "A custom security policy defined in IBM SCC was violated.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 75,
        "resource": "ibm_scc_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "event_type",   "op": "equals", "value": "POLICY_VIOLATION"},
        ]}},
    },
    {
        "rule_id": "ibm.scc.audit.posture_degradation",
        "service": "scc", "severity": "high",
        "title": "IBM SCC: Security Posture Score Degraded",
        "description": "The overall IBM SCC security posture score degraded significantly, indicating multiple new failures or a systemic configuration change.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 72,
        "resource": "ibm_scc_profile",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "event_type",   "op": "equals", "value": "POSTURE_DEGRADATION"},
        ]}},
    },
    {
        "rule_id": "ibm.scc.audit.config_drift",
        "service": "scc", "severity": "medium",
        "title": "IBM SCC: Configuration Drift Detected",
        "description": "IBM SCC detected configuration drift from a previously compliant baseline. Drift may indicate unauthorized infrastructure changes.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 65,
        "resource": "ibm_scc_profile",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "ibm_scc"},
            {"field": "event_type",   "op": "equals", "value": "CONFIG_DRIFT"},
        ]}},
    },

    # ── Database / DB Services ────────────────────────────────────────────
    {
        "rule_id": "ibm.db.activity.instance_deleted",
        "service": "db", "severity": "critical",
        "title": "IBM Databases: Service Instance Deleted",
        "description": "An IBM Cloud database service instance (PostgreSQL, MySQL, Db2, Redis, etc.) was deleted. Instance deletion results in permanent data loss.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 95,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_activity"},
            {"field": "operation",   "op": "in", "value": [
                "databases-for-postgresql.instance.delete",
                "databases-for-mysql.instance.delete",
                "databases-for-redis.instance.delete",
                "databases-for-mongodb.instance.delete",
                "databases-for-elasticsearch.instance.delete",
            ]},
        ]}},
    },
    {
        "rule_id": "ibm.db.activity.db_admin_activity",
        "service": "db", "severity": "high",
        "title": "IBM DB Audit: Privileged Admin Activity",
        "description": "Privileged database admin activity was recorded in IBM DB audit logs. Unauthorized admin operations can exfiltrate data or modify database schema.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1078"],
        "risk_score": 80,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",   "op": "equals", "value": "ibm_db_audit"},
            {"field": "privilege_used","op": "in", "value": ["SYSDBA", "DBA", "SUPERUSER"]},
        ]}},
    },
    {
        "rule_id": "ibm.db.activity.db_failed_login",
        "service": "db", "severity": "medium",
        "title": "IBM DB Audit: Failed Database Login",
        "description": "Multiple failed login attempts were recorded in IBM database audit logs, indicating potential brute force.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1110"],
        "risk_score": 68,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",   "op": "equals", "value": "ibm_db_audit"},
            {"field": "action",        "op": "equals", "value": "LOGON"},
            {"field": "return_code",   "op": "not_equals", "value": 0},
        ]}},
    },
    {
        "rule_id": "ibm.db.activity.db_schema_change",
        "service": "db", "severity": "high",
        "title": "IBM DB Audit: DDL Schema Change",
        "description": "A DDL statement (DROP TABLE, ALTER TABLE, TRUNCATE) was executed in an IBM database. Unauthorized schema changes destroy data or bypass security controls.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 82,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_db_audit"},
            {"field": "action",      "op": "in", "value": ["DROP_TABLE", "ALTER_TABLE", "TRUNCATE"]},
        ]}},
    },
    {
        "rule_id": "ibm.db.activity.audit_config_change",
        "service": "db", "severity": "high",
        "title": "IBM DB Audit: Audit Configuration Changed",
        "description": "Database audit configuration was modified. Disabling audit policies removes forensic evidence of future database activity.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 80,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_db_audit"},
            {"field": "action",      "op": "in", "value": ["AUDIT_POLICY_CHANGE", "AUDIT_TRAIL_DELETE"]},
        ]}},
    },
    {
        "rule_id": "ibm.db.activity.user_management",
        "service": "db", "severity": "high",
        "title": "IBM DB Audit: Database User Created or Privilege Granted",
        "description": "A new database user was created or DBA privileges were granted. Unauthorized user creation enables persistent database access.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136"],
        "risk_score": 78,
        "resource": "ibm_database_instance",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "ibm_db_audit"},
            {"field": "action",      "op": "in", "value": ["CREATE_USER", "GRANT_PRIVILEGE", "ALTER_USER"]},
        ]}},
    },

    # ── CIEM Correlation Chains ────────────────────────────────────────────
    {
        "rule_id": "ibm.ciem.chain.privilege_escalation_via_trusted_profile",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "IBM CIEM: Privilege Escalation via Trusted Profile + IAM Policy Change",
        "description": "Detect IBM Cloud privilege escalation: trusted profile created/modified → IAM policy granting Administrator role → privileged API calls, indicating a multi-step takeover.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 98,
        "resource": "ibm_iam_trusted_profile",
        "check_config": {
            "type": "sequence",
            "window_seconds": 600,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["iam-identity.profile.create", "iam-identity.profile.update"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["iam-am.policy.create", "iam-am.policy.update"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "ibm.ciem.chain.data_exfiltration_via_cos",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "IBM CIEM: Data Exfiltration via COS Bucket Public Access",
        "description": "Detect a data exfiltration pattern: COS bucket made public or policy changed → bulk object access from unexpected source, indicating unauthorized data retrieval.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "risk_score": 97,
        "resource": "ibm_cos_bucket",
        "check_config": {
            "type": "sequence",
            "window_seconds": 900,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["cloud-object-storage.bucket-acl.update", "cloud-object-storage.bucket-policy.create"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["cloud-object-storage.object.read", "cloud-object-storage.bucket.list"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "ibm.ciem.chain.defense_evasion_log_destroy",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "IBM CIEM: Defense Evasion via Activity Tracker Deletion + MFA Disable",
        "description": "Detect an evidence destruction chain: Activity Tracker instance deleted + MFA settings weakened within a short window, indicating an attacker removing audit visibility and weakening authentication.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562"],
        "risk_score": 99,
        "resource": "ibm_logdna_instance",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["logdnaat.instance.delete", "atracker.route.delete"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "ibm_activity"},
                    {"field": "operation",   "op": "in", "value": ["iam-identity.accountsettings.update", "iam-identity.mfaenrollment.update"]},
                ]}},
            ],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Generator helpers
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
    if "type" in cond:
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
    parts = rid.split(".")
    svc = parts[1] if len(parts) > 1 else "general"
    check_type = rule.get("check_type", "log")
    tactics_str = "[" + ", ".join(rule.get("mitre_tactics", [])) + "]"
    techniques_str = "[" + ", ".join(rule.get("mitre_techniques", [])) + "]"
    frameworks = '["SOC2", "ISO27001"]'
    check_config = rule.get("check_config", {})

    lines: list[str] = [
        f"rule_id: {rid}",
        f"provider: ibm",
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
        "remediation: Review and investigate this activity in the IBM Cloud Console and take corrective action.",
        "check_config:",
    ]

    if "type" in check_config:
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
