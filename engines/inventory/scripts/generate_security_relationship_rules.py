#!/usr/bin/env python3
"""
generate_security_relationship_rules.py
Enterprise-grade generator for resource_security_relationship_rules.

Generates relationship rules for ALL CSPs based on:
  1. resource_inventory_identifier  — exact resource types that inventory processes
  2. Field-pattern heuristics       — well-known field → relationship mappings per CSP
  3. Existing rules                 — kept untouched (fully idempotent)

Usage
─────
  # Show what would be inserted without writing (safest first run)
  python generate_security_relationship_rules.py --dry-run

  # Run for specific CSPs only
  python generate_security_relationship_rules.py --csp aws,azure,gcp

  # Check how many inventoried types have rules (no DB writes)
  python generate_security_relationship_rules.py --validate

  # Tune batch size and retry count
  python generate_security_relationship_rules.py --batch-size 500 --retries 5

  # Full run with debug logging
  python generate_security_relationship_rules.py -v

Environment Variables
─────────────────────
  INVENTORY_DB_HOST     (default: localhost)
  INVENTORY_DB_PORT     (default: 5432)
  INVENTORY_DB_NAME     (default: threat_engine_inventory)
  INVENTORY_DB_USER     (default: postgres)
  INVENTORY_DB_PASSWORD (default: "")

Exit Codes
──────────
  0  All CSPs processed successfully
  1  Partial failure (≥1 CSP failed, others succeeded)
  2  Fatal error (schema invalid, DB unreachable, bad arguments)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psycopg2
import psycopg2.extensions
import psycopg2.extras

# ──────────────────────────────────────────────────────────────────────────────
# Logging — ISO-8601 timestamps, padded level field
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("rules-generator")

# ──────────────────────────────────────────────────────────────────────────────
# FIELD-PATTERN TEMPLATES PER CSP
#
# Each tuple:  (source_field, relation_type, to_resource_type, target_uid_pattern)
#
# source_field       — dot-notation path into emitted_fields (top-level or nested)
# relation_type      — matches RelationType enum in schemas/relationship_schema.py
# to_resource_type   — EXACT type stored in resource_security_relationship_rules
# target_uid_pattern — substitution template:
#                        {value}      → the raw field value (scalar)
#                        {item}       → each element of a list field
#                        {FieldName}  → a sub-key inside each list object
#                        {region}     → resolved from the asset's region
#                        {account_id} → resolved from the asset's account_id
# ──────────────────────────────────────────────────────────────────────────────

AWS_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network containment ─────────────────────────────────────────────────────
    ("VpcId",                                         "in_vpc",        "ec2.vpc",               "arn:aws:ec2:{region}:{account_id}:vpc/{value}"),
    ("Vpc.VpcId",                                     "in_vpc",        "ec2.vpc",               "arn:aws:ec2:{region}:{account_id}:vpc/{value}"),
    ("VpcConfig.VpcId",                               "in_vpc",        "ec2.vpc",               "arn:aws:ec2:{region}:{account_id}:vpc/{value}"),
    ("Network.VpcId",                                 "in_vpc",        "ec2.vpc",               "arn:aws:ec2:{region}:{account_id}:vpc/{value}"),
    ("DBSubnetGroup.VpcId",                           "in_vpc",        "ec2.vpc",               "arn:aws:ec2:{region}:{account_id}:vpc/{value}"),
    # Subnets
    ("SubnetId",                                      "in_subnet",     "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{value}"),
    ("SubnetIds",                                     "in_subnet",     "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    ("VpcConfig.SubnetIds",                           "in_subnet",     "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    ("DBSubnetGroup.Subnets",                         "in_subnet",     "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetIdentifier}"),
    ("networkConfiguration.awsvpcConfiguration.subnets", "in_subnet", "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    ("resourcesVpcConfig.subnetIds",                  "in_subnet",     "ec2.subnet",            "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    # Security groups
    ("SecurityGroupId",                               "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{value}"),
    ("SecurityGroupIds",                              "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    ("SecurityGroups",                                "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"),
    ("VpcConfig.SecurityGroupIds",                    "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    ("VpcSecurityGroups",                             "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}"),
    ("networkConfiguration.awsvpcConfiguration.securityGroups", "has_sg", "ec2.security-group", "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    ("resourcesVpcConfig.securityGroupIds",           "has_sg",        "ec2.security-group",    "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    # ── IAM / Identity ─────────────────────────────────────────────────────────
    ("RoleArn",                                       "assumes",       "iam.role",              "{value}"),
    ("Role",                                          "assumes",       "iam.role",              "{value}"),
    ("taskRoleArn",                                   "assumes",       "iam.role",              "{value}"),
    ("executionRoleArn",                              "assumes",       "iam.role",              "{value}"),
    ("roleArn",                                       "assumes",       "iam.role",              "{value}"),
    ("IamRoleArn",                                    "assumes",       "iam.role",              "{value}"),
    ("ServiceRoleArn",                                "assumes",       "iam.role",              "{value}"),
    ("IamInstanceProfile.Arn",                        "has_profile",   "iam.instance-profile",  "{value}"),
    ("InstanceProfileArn",                            "has_profile",   "iam.instance-profile",  "{value}"),
    # ── Encryption / KMS ────────────────────────────────────────────────────────
    ("KmsKeyId",                                      "encrypted_by",  "kms.key",               "{value}"),
    ("KmsKeyArn",                                     "encrypted_by",  "kms.key",               "{value}"),
    ("KMSKeyId",                                      "encrypted_by",  "kms.key",               "{value}"),
    ("SSEDescription.KMSMasterKeyID",                 "encrypted_by",  "kms.key",               "{value}"),
    ("StorageEncrypted",                              "encrypted_by",  "kms.key",               "{KmsKeyId}"),
    ("MasterKeyAlias",                                "encrypted_by",  "kms.alias",             "arn:aws:kms:{region}:{account_id}:alias/{value}"),
    # ── Storage / Volumes ────────────────────────────────────────────────────────
    ("BlockDeviceMappings",                           "has_volume",    "ec2.volume",            "arn:aws:ec2:{region}:{account_id}:volume/{Ebs.VolumeId}"),
    ("Attachments",                                   "attached_to",   "ec2.volume",            "arn:aws:ec2:{region}:{account_id}:volume/{VolumeId}"),
    # ── Network interfaces ───────────────────────────────────────────────────────
    ("NetworkInterfaceId",                            "has_eni",       "ec2.network-interface", "arn:aws:ec2:{region}:{account_id}:network-interface/{value}"),
    ("NetworkInterfaces",                             "has_eni",       "ec2.network-interface", "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}"),
    # ── Logging / monitoring ─────────────────────────────────────────────────────
    ("LoggingConfiguration.TargetBucket",             "logging_enabled_to", "s3.bucket",        "arn:aws:s3:::{value}"),
    ("S3BucketName",                                  "logging_enabled_to", "s3.bucket",        "arn:aws:s3:::{value}"),
    ("CloudWatchLogsLogGroupArn",                     "logging_enabled_to", "logs.log-group",   "{value}"),
    ("LogGroupName",                                  "logging_enabled_to", "logs.log-group",   "arn:aws:logs:{region}:{account_id}:log-group:{value}"),
    ("Logging.TargetBucket",                          "logging_enabled_to", "s3.bucket",        "arn:aws:s3:::{value}"),
    ("LogDeliveryConfiguration.SnsTopic",             "logging_enabled_to", "sns.topic",        "{value}"),
    # ── Load balancing ────────────────────────────────────────────────────────────
    ("LoadBalancerArn",                               "attached_to",   "elbv2.load-balancer",  "{value}"),
    ("TargetGroupArns",                               "routes_to",     "elbv2.target-group",   "{item}"),
    # ── Certificate / WAF ─────────────────────────────────────────────────────────
    ("CertificateArn",                                "uses",          "acm.certificate",      "{value}"),
    ("SslCertificateId",                              "uses",          "acm.certificate",      "{value}"),
    ("WebAclId",                                      "protected_by",  "waf.web-acl",          "{value}"),
    ("WebAclArn",                                     "protected_by",  "waf.web-acl",          "{value}"),
    # ── SNS / SQS ─────────────────────────────────────────────────────────────────
    ("TopicArn",                                      "publishes_to",  "sns.topic",            "{value}"),
    ("QueueArn",                                      "subscribes_to", "sqs.queue",            "{value}"),
    # ── S3 replication ────────────────────────────────────────────────────────────
    ("ReplicationConfiguration.Rules",                "replicates_to", "s3.bucket",            "{Destination.Bucket}"),
    # ── CloudTrail ─────────────────────────────────────────────────────────────────
    ("TrailARN",                                      "monitored_by",  "cloudtrail.trail",     "{value}"),
]

AZURE_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network containment ─────────────────────────────────────────────────────
    ("subnetId",                                           "in_subnet",     "network.subnets",               "{value}"),
    ("properties.subnet.id",                               "in_subnet",     "network.subnets",               "{value}"),
    ("network.delegatedSubnetResourceId",                  "in_subnet",     "network.subnets",               "{value}"),
    ("properties.agentPoolProfiles",                       "in_subnet",     "network.subnets",               "{vnetSubnetID}"),
    ("properties.virtualNetwork.id",                       "in_vnet",       "network.virtualnetworks",       "{value}"),
    ("properties.networkProfile.networkInterfaces",        "has_nic",       "network.networkinterfaces",     "{id}"),
    ("networkProfile.networkInterfaces",                   "has_nic",       "network.networkinterfaces",     "{value}"),
    # NSG
    ("properties.networkSecurityGroup.id",                 "has_nsg",       "network.networksecuritygroups", "{value}"),
    ("networkSecurityGroup.id",                            "has_nsg",       "network.networksecuritygroups", "{value}"),
    # ── Identity ───────────────────────────────────────────────────────────────
    ("identity.userAssignedIdentities",                    "uses",          "managedidentity.userassignedidentities", "{id}"),
    ("properties.identity.principalId",                    "has_identity",  "managedidentity.userassignedidentities", "{value}"),
    # ── Encryption ─────────────────────────────────────────────────────────────
    ("properties.encryption.keyVaultProperties.keyVaultUri", "encrypted_by", "keyvault.vaults",             "{value}"),
    ("encryption.keyVaultProperties.keyVaultUri",           "encrypted_by",  "keyvault.vaults",             "{value}"),
    ("encryption.diskEncryptionSetId",                     "encrypted_by",  "keyvault.vaults",               "{value}"),
    # ── Storage / Disk ──────────────────────────────────────────────────────────
    ("properties.storageProfile.osDisk.managedDisk.id",    "has_os_disk",   "compute.disks",                 "{value}"),
    ("properties.storageProfile.dataDisks",                "has_disk",      "compute.disks",                 "{managedDisk.id}"),
    ("storageProfile.osDisk.managedDisk.id",               "has_os_disk",   "compute.disks",                 "{value}"),
    ("storageProfile.dataDisks",                           "has_disk",      "compute.disks",                 "{managedDisk.id}"),
    # ── Resource group containment ───────────────────────────────────────────────
    ("resourceGroup",                                      "contained_by",  "resources.resourcegroups",      "/subscriptions/{subscriptionId}/resourceGroups/{value}"),
    # ── Key Vault secrets ─────────────────────────────────────────────────────────
    ("properties.addonProfiles.azureKeyvaultSecretsProvider.identity.clientId", "uses", "keyvault.vaults", "{value}"),
    # ── Monitoring / Logging ──────────────────────────────────────────────────────
    ("properties.storageAccountId",                        "logging_enabled_to", "storage.storageaccounts",  "{value}"),
    ("storageAccountId",                                   "logging_enabled_to", "storage.storageaccounts",  "{value}"),
    # ── Load Balancer / Public IP ─────────────────────────────────────────────────
    ("properties.backendAddressPools",                     "routes_to",     "network.loadbalancers",         "{id}"),
    ("properties.frontendIPConfigurations",                "uses",          "network.publicipaddresses",     "{publicIPAddress.id}"),
]

GCP_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network ────────────────────────────────────────────────────────────────
    ("network",                                        "in_network",    "compute.network",       "{value}"),
    ("networkInterfaces",                              "in_network",    "compute.network",       "{network}"),
    ("subnetwork",                                     "in_subnet",     "compute.subnetwork",    "{value}"),
    ("networkInterfaces",                              "in_subnet",     "compute.subnetwork",    "{subnetwork}"),
    ("network",                                        "has_firewall",  "compute.firewall",      "{value}"),
    # ── IAM / Service Account ─────────────────────────────────────────────────
    ("serviceAccount",                                 "uses",          "iam.serviceaccount",    "{value}"),
    ("serviceAccounts",                                "uses",          "iam.serviceaccount",    "{email}"),
    ("serviceAccountEmail",                            "uses",          "iam.serviceaccount",    "projects/{account_id}/serviceAccounts/{value}"),
    ("nodeConfig.serviceAccount",                      "uses",          "iam.serviceaccount",    "projects/{account_id}/serviceAccounts/{value}"),
    # ── Encryption / KMS ──────────────────────────────────────────────────────
    ("kmsKeyName",                                     "encrypted_by",  "cloudkms.cryptokey",    "{value}"),
    ("diskEncryptionKey.kmsKeyName",                   "encrypted_by",  "cloudkms.cryptokey",    "{value}"),
    ("defaultEncryptionConfiguration.kmsKeyName",      "encrypted_by",  "cloudkms.cryptokey",    "{value}"),
    ("encryptionConfiguration.kmsKeyName",             "encrypted_by",  "cloudkms.cryptokey",    "{value}"),
    ("bootDiskKmsKey",                                 "encrypted_by",  "cloudkms.cryptokey",    "{value}"),
    # ── Storage ────────────────────────────────────────────────────────────────
    ("bucket",                                         "stores_data_in","storage.bucket",        "projects/_/buckets/{value}"),
    # ── Logging ────────────────────────────────────────────────────────────────
    ("logBucket",                                      "logging_enabled_to", "logging.logbucket", "{value}"),
    ("destination",                                    "logging_enabled_to", "logging.logsink",   "{value}"),
    # ── Pub/Sub ────────────────────────────────────────────────────────────────
    ("topic",                                          "publishes_to",  "pubsub.topic",          "{value}"),
    ("pushConfig.pushEndpoint",                        "triggers",      "run.service",           "{value}"),
    # ── Load Balancer ──────────────────────────────────────────────────────────
    ("backend",                                        "routes_to",     "compute.backendservice", "{value}"),
    # ── GKE ────────────────────────────────────────────────────────────────────
    ("network",                                        "attached_to",   "compute.network",       "{value}"),
    ("subnetwork",                                     "attached_to",   "compute.subnetwork",    "{value}"),
]

OCI_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network ────────────────────────────────────────────────────────────────
    ("vcnId",                                          "in_vcn",        "core.vcn",                      "{value}"),
    ("subnetId",                                       "in_subnet",     "core.subnet",                   "{value}"),
    ("networkSecurityGroupIds",                        "has_sg",        "core.networksecuritygroup",      "{item}"),
    ("nsgIds",                                         "has_sg",        "core.networksecuritygroup",      "{item}"),
    # ── Compartment containment ────────────────────────────────────────────────
    ("compartmentId",                                  "contained_by",  "identity.compartment",          "{value}"),
    # ── Encryption / KMS ──────────────────────────────────────────────────────
    ("kmsKeyId",                                       "encrypted_by",  "keymanagement.key",             "{value}"),
    ("definedTags",                                    "encrypted_by",  "keymanagement.key",             "{Oracle-Tags.kmsKeyId}"),
    # ── Storage / Volumes ──────────────────────────────────────────────────────
    ("bootVolumeId",                                   "has_volume",    "blockstorage.volume",           "{value}"),
    ("volumeId",                                       "attached_to",   "blockstorage.volume",           "{value}"),
    # ── Load Balancer ─────────────────────────────────────────────────────────
    ("loadBalancerId",                                 "attached_to",   "loadbalancer.loadbalancer",     "{value}"),
    ("backendSetName",                                 "routes_to",     "loadbalancer.backend",          "{value}"),
    # ── DNS ────────────────────────────────────────────────────────────────────
    ("zoneId",                                         "contained_by",  "dns.zone",                      "{value}"),
    # ── Serverless / Functions ─────────────────────────────────────────────────
    ("applicationId",                                  "contained_by",  "functions.application",         "{value}"),
    # ── Logging ────────────────────────────────────────────────────────────────
    ("logGroupId",                                     "logging_enabled_to", "logging.loggroup",         "{value}"),
    ("objectName",                                     "stores_data_in",     "objectstorage.bucket",     "{value}"),
]

IBM_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network ────────────────────────────────────────────────────────────────
    ("vpc.id",                                         "in_vpc",        "is.vpc",                        "{value}"),
    ("subnet.id",                                      "in_subnet",     "is.subnet",                     "{value}"),
    ("security_groups",                                "has_sg",        "is.securitygroup",              "{id}"),
    # ── Volumes ────────────────────────────────────────────────────────────────
    ("volume_attachments",                             "has_volume",    "is.volume",                     "{volume.id}"),
    ("boot_volume_attachment.volume.id",               "has_volume",    "is.volume",                     "{value}"),
    # ── IAM ────────────────────────────────────────────────────────────────────
    ("crn",                                            "uses",          "iam.serviceId",                 "{value}"),
    # ── Encryption ─────────────────────────────────────────────────────────────
    ("encryption_key.crn",                             "encrypted_by",  "kp.key",                        "{value}"),
    # ── Load Balancer ─────────────────────────────────────────────────────────
    ("load_balancer.id",                               "attached_to",   "is.loadbalancer",               "{value}"),
    # ── Object Storage ────────────────────────────────────────────────────────
    ("bucket_name",                                    "stores_data_in","ibm.cos.bucket",                "{value}"),
    # ── Floating IP ────────────────────────────────────────────────────────────
    ("floating_ips",                                   "uses",          "is.floatingip",                 "{id}"),
    # ── Resource Group containment ────────────────────────────────────────────
    ("resource_group.id",                              "contained_by",  "resource-controller.resource-group", "{value}"),
]

ALICLOUD_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Network ────────────────────────────────────────────────────────────────
    ("VpcId",                                          "in_vpc",        "vpc.vpc",               "acs:vpc:{region}:{account_id}:vpc/{value}"),
    ("VSwitchId",                                      "in_subnet",     "vpc.vswitch",           "acs:vpc:{region}:{account_id}:vswitch/{value}"),
    ("SecurityGroupIds",                               "has_sg",        "ecs.securitygroup",     "acs:ecs:{region}:{account_id}:securitygroup/{item}"),
    ("SecurityGroupId",                                "has_sg",        "ecs.securitygroup",     "acs:ecs:{region}:{account_id}:securitygroup/{value}"),
    # ── IAM ────────────────────────────────────────────────────────────────────
    ("RamRoleName",                                    "assumes",       "ram.role",              "{value}"),
    ("PolicyName",                                     "has_policy",    "ram.policy",            "{value}"),
    # ── Encryption ─────────────────────────────────────────────────────────────
    ("KMSKeyId",                                       "encrypted_by",  "kms.key",               "{value}"),
    # ── Storage ────────────────────────────────────────────────────────────────
    ("OssBucketName",                                  "stores_data_in","oss.bucket",            "{value}"),
    ("DiskIds",                                        "has_volume",    "ecs.disk",              "{item}"),
    # ── Load Balancer ─────────────────────────────────────────────────────────
    ("LoadBalancerId",                                 "attached_to",   "slb.loadbalancer",      "{value}"),
    # ── Logging ────────────────────────────────────────────────────────────────
    ("LogProject",                                     "logging_enabled_to", "log.project",      "{value}"),
]

K8S_TEMPLATES: List[Tuple[str, str, str, str]] = [
    # ── Namespace containment ──────────────────────────────────────────────────
    ("metadata.namespace",                             "contained_by",  "namespace.k8s.core/namespace",                       "{value}"),
    ("namespace",                                      "contained_by",  "namespace.k8s.core/namespace",                       "{value}"),
    # ── Service Account ────────────────────────────────────────────────────────
    ("spec.serviceAccountName",                        "uses",          "serviceaccount.k8s.core/serviceaccount",             "{value}"),
    ("serviceAccountName",                             "uses",          "serviceaccount.k8s.core/serviceaccount",             "{value}"),
    # ── Deployments / Scaling ──────────────────────────────────────────────────
    ("spec.selector.matchLabels",                      "scales_with",   "deployment.k8s.apps/deployment",                     "{value}"),
    # ── Ingress routing ────────────────────────────────────────────────────────
    ("spec.rules",                                     "routes_to",     "service.k8s.core/service",                           "{http.paths.backend.service.name}"),
    # ── Secrets ────────────────────────────────────────────────────────────────
    ("spec.volumes",                                   "uses",          "secret.k8s.core/secret",                             "{secret.secretName}"),
    ("spec.imagePullSecrets",                          "uses",          "secret.k8s.core/secret",                             "{name}"),
    # ── ConfigMaps ─────────────────────────────────────────────────────────────
    ("spec.volumes",                                   "uses",          "configmap.k8s.core/configmap",                       "{configMap.name}"),
    # ── Persistent Volumes ────────────────────────────────────────────────────
    ("spec.volumes",                                   "uses",          "persistentvolumeclaim.k8s.core/persistentvolumeclaim", "{persistentVolumeClaim.claimName}"),
    ("spec.volumeName",                                "attached_to",   "persistentvolume.k8s.core/persistentvolume",         "{value}"),
    # ── Network Policy ────────────────────────────────────────────────────────
    ("spec.podSelector",                               "restricted_to", "networkpolicy.k8s.networking.k8s.io/networkpolicy",  "{value}"),
]

# Map CSP name → templates list
CSP_TEMPLATES: Dict[str, List[Tuple[str, str, str, str]]] = {
    "aws":      AWS_TEMPLATES,
    "azure":    AZURE_TEMPLATES,
    "gcp":      GCP_TEMPLATES,
    "oci":      OCI_TEMPLATES,
    "ibm":      IBM_TEMPLATES,
    "alicloud": ALICLOUD_TEMPLATES,
    "k8s":      K8S_TEMPLATES,
}

# ──────────────────────────────────────────────────────────────────────────────
# Schema requirements checked before any writes
# ──────────────────────────────────────────────────────────────────────────────

_REQUIRED_COLUMNS: Dict[str, Set[str]] = {
    "resource_security_relationship_rules": {
        "csp", "from_resource_type", "relation_type", "to_resource_type",
        "source_field", "source_field_item", "target_uid_pattern", "is_active",
    },
    "resource_inventory_identifier": {
        "csp", "resource_type", "should_inventory",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleRecord:
    csp: str
    from_resource_type: str
    relation_type: str
    to_resource_type: str
    source_field: str
    source_field_item: Optional[str]
    target_uid_pattern: str

    def db_tuple(self) -> tuple:
        return (
            self.csp,
            self.from_resource_type,
            self.relation_type,
            self.to_resource_type,
            self.source_field,
            self.source_field_item,
            self.target_uid_pattern,
            True,  # is_active
        )


@dataclass
class CSPResult:
    csp: str
    inventoried_types: int = 0
    templates: int = 0
    candidates: int = 0     # new rules computed (before insert)
    skipped: int = 0        # already existed (dedup)
    inserted: int = 0       # rows actually written (rowcount from DB)
    failed: bool = False
    error: str = ""
    elapsed_s: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# DB connection with exponential-backoff retry
# ──────────────────────────────────────────────────────────────────────────────

def _db_params() -> dict:
    return dict(
        host=os.environ.get("INVENTORY_DB_HOST", "localhost"),
        port=int(os.environ.get("INVENTORY_DB_PORT", "5432")),
        dbname=os.environ.get("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.environ.get("INVENTORY_DB_USER", "postgres"),
        password=os.environ.get("INVENTORY_DB_PASSWORD", ""),
    )


def connect_with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
) -> psycopg2.extensions.connection:
    """Connect to PostgreSQL, retrying with exponential back-off on failure."""
    params = _db_params()
    last_exc: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            conn = psycopg2.connect(**params)
            conn.autocommit = False
            log.info(
                "Connected  host=%s:%s  db=%s  user=%s",
                params["host"], params["port"], params["dbname"], params["user"],
            )
            return conn
        except psycopg2.OperationalError as exc:
            last_exc = exc
            delay = base_delay * (2 ** (attempt - 1))
            if attempt < max_attempts:
                log.warning(
                    "Connection attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_attempts, exc, delay,
                )
                time.sleep(delay)
            else:
                log.error("All %d connection attempts failed.", max_attempts)

    raise ConnectionError(
        f"Could not connect after {max_attempts} attempts: {last_exc}"
    ) from last_exc


# ──────────────────────────────────────────────────────────────────────────────
# Schema validation
# ──────────────────────────────────────────────────────────────────────────────

def validate_schema(conn: psycopg2.extensions.connection) -> None:
    """
    Verify that all required tables and columns exist.
    Raises RuntimeError with a descriptive message on any mismatch.
    """
    log.info("Validating database schema...")
    with conn.cursor() as cur:
        for table, required_cols in _REQUIRED_COLUMNS.items():
            cur.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s
                """,
                (table,),
            )
            actual_cols = {row[0] for row in cur.fetchall()}
            if not actual_cols:
                raise RuntimeError(
                    f"Required table '{table}' does not exist in database. "
                    f"Have you run the inventory migration?"
                )
            missing = required_cols - actual_cols
            if missing:
                raise RuntimeError(
                    f"Table '{table}' is missing required columns: {sorted(missing)}"
                )
    log.info("Schema validation passed.")


# ──────────────────────────────────────────────────────────────────────────────
# Data loaders
# ──────────────────────────────────────────────────────────────────────────────

def load_inventoried_types(
    conn: psycopg2.extensions.connection,
    csp: str,
) -> Set[str]:
    """Return resource types that are actively inventoried for this CSP."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT resource_type
            FROM resource_inventory_identifier
            WHERE csp = %s AND should_inventory = true
            """,
            (csp,),
        )
        return {row[0] for row in cur.fetchall()}


def load_existing_rules(
    conn: psycopg2.extensions.connection,
    csp: str,
) -> Set[Tuple[str, str, str, str]]:
    """
    Return (from_type, relation_type, to_type, source_field) tuples for all
    existing rules for this CSP. Used to avoid re-inserting duplicates.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT from_resource_type, relation_type, to_resource_type, source_field
            FROM resource_security_relationship_rules
            WHERE csp = %s
            """,
            (csp,),
        )
        return {(r[0], r[1], r[2], r[3]) for r in cur.fetchall()}


# ──────────────────────────────────────────────────────────────────────────────
# Rule building
# ──────────────────────────────────────────────────────────────────────────────

_TEMPLATE_VARS = frozenset({"region", "account_id", "subscriptionId"})


def _resolve_source_field_item(pattern: str) -> Optional[str]:
    """
    Determine source_field_item from the target_uid_pattern.

    Logic:
      {item}     → the field is a list; yield each element directly  → "item"
      {value}    → scalar field                                       → None
      {OtherKey} → a sub-key within each list object                  → "OtherKey"
      {dot.path} → a nested sub-key within each list object           → "dot.path"
      Template variables ({region}, {account_id}) are ignored.
    """
    if "{item}" in pattern:
        return "item"
    if "{value}" in pattern:
        return None

    # Collect all {placeholder} tokens, excluding known template vars
    placeholders = []
    buf = pattern
    while "{" in buf:
        s = buf.index("{") + 1
        e = buf.index("}", s)
        token = buf[s:e]
        if token not in _TEMPLATE_VARS:
            placeholders.append(token)
        buf = buf[e + 1:]

    if len(placeholders) == 1:
        return placeholders[0]
    if len(placeholders) > 1:
        # Multiple data placeholders: return the first non-trivial one
        return placeholders[0]
    return None


def build_rules_for_csp(
    inventoried: Set[str],
    existing: Set[Tuple[str, str, str, str]],
    templates: List[Tuple[str, str, str, str]],
    csp: str,
) -> Tuple[List[RuleRecord], int]:
    """
    Build the list of new RuleRecord objects for a CSP.

    Cross-products inventoried_types × templates, skipping any combination
    that already exists in the DB.

    Returns:
        (new_rules, skipped_count)
    """
    new_rules: List[RuleRecord] = []
    skipped = 0

    for resource_type in sorted(inventoried):
        for source_field, relation_type, to_type, pattern in templates:
            dedup_key = (resource_type, relation_type, to_type, source_field)
            if dedup_key in existing:
                skipped += 1
                continue

            new_rules.append(
                RuleRecord(
                    csp=csp,
                    from_resource_type=resource_type,
                    relation_type=relation_type,
                    to_resource_type=to_type,
                    source_field=source_field,
                    source_field_item=_resolve_source_field_item(pattern),
                    target_uid_pattern=pattern,
                )
            )

    return new_rules, skipped


# ──────────────────────────────────────────────────────────────────────────────
# Batch insert
# ──────────────────────────────────────────────────────────────────────────────

def insert_rules_batched(
    conn: psycopg2.extensions.connection,
    rules: List[RuleRecord],
    batch_size: int,
) -> int:
    """
    Insert rules in batches inside a single transaction (per-CSP isolation).

    Uses ON CONFLICT DO NOTHING so re-runs are safe.
    Returns the total number of rows actually written (psycopg2 rowcount).
    """
    if not rules:
        return 0

    total = 0
    n_batches = (len(rules) + batch_size - 1) // batch_size

    for i, start in enumerate(range(0, len(rules), batch_size), 1):
        batch = rules[start : start + batch_size]
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO resource_security_relationship_rules
                  (csp, from_resource_type, relation_type, to_resource_type,
                   source_field, source_field_item, target_uid_pattern, is_active)
                VALUES %s
                ON CONFLICT DO NOTHING
                """,
                [r.db_tuple() for r in batch],
            )
            batch_inserted = cur.rowcount
            total += batch_inserted
            log.debug(
                "  Batch %d/%d: %d rows submitted → %d inserted",
                i, n_batches, len(batch), batch_inserted,
            )

    conn.commit()
    return total


# ──────────────────────────────────────────────────────────────────────────────
# Dry-run output
# ──────────────────────────────────────────────────────────────────────────────

def print_dry_run_rules(rules: List[RuleRecord]) -> None:
    """Print rules to stdout in a structured format (no DB writes)."""
    for r in rules:
        print(
            f"[DRY-RUN]  csp={r.csp:<10}  "
            f"{r.from_resource_type:<42}  --{r.relation_type}-->  "
            f"{r.to_resource_type:<42}  "
            f"field={r.source_field}  "
            f"item={r.source_field_item or '-'}  "
            f"pattern={r.target_uid_pattern}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Per-CSP processor (handles its own rollback on failure)
# ──────────────────────────────────────────────────────────────────────────────

def process_csp(
    conn: psycopg2.extensions.connection,
    csp: str,
    dry_run: bool,
    batch_size: int,
) -> CSPResult:
    result = CSPResult(csp=csp)
    t0 = time.monotonic()

    try:
        templates = CSP_TEMPLATES.get(csp, [])
        result.templates = len(templates)

        if not templates:
            log.warning("[%s] No templates defined — skipping", csp.upper())
            result.elapsed_s = time.monotonic() - t0
            return result

        inventoried = load_inventoried_types(conn, csp)
        existing    = load_existing_rules(conn, csp)
        result.inventoried_types = len(inventoried)

        log.info(
            "[%s] inventoried_types=%d  existing_rules=%d  templates=%d",
            csp.upper(), len(inventoried), len(existing), len(templates),
        )

        if not inventoried:
            log.warning(
                "[%s] No inventoried types found — check resource_inventory_identifier.should_inventory",
                csp.upper(),
            )
            result.elapsed_s = time.monotonic() - t0
            return result

        new_rules, skipped = build_rules_for_csp(inventoried, existing, templates, csp)
        result.candidates = len(new_rules)
        result.skipped    = skipped

        log.info(
            "[%s] candidates=%d  already_exist=%d  to_insert=%d",
            csp.upper(), len(new_rules) + skipped, skipped, len(new_rules),
        )

        if dry_run:
            print_dry_run_rules(new_rules)
            result.inserted = len(new_rules)  # show what would be inserted
        else:
            try:
                result.inserted = insert_rules_batched(conn, new_rules, batch_size)
            except psycopg2.Error as db_exc:
                conn.rollback()
                result.failed = True
                result.error  = str(db_exc)
                log.error("[%s] DB error — transaction rolled back: %s", csp.upper(), db_exc)

    except Exception as exc:
        result.failed = True
        result.error  = str(exc)
        log.error("[%s] Unexpected error: %s", csp.upper(), exc, exc_info=True)

    result.elapsed_s = time.monotonic() - t0
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Coverage validation (read-only analysis, no writes)
# ──────────────────────────────────────────────────────────────────────────────

def run_coverage_validation(
    conn: psycopg2.extensions.connection,
    csps: List[str],
) -> None:
    """
    Print a coverage report: how many inventoried types have ≥1 rule in the DB.
    Highlights uncovered types so they can be added to templates.
    """
    print()
    print("=" * 90)
    print("  COVERAGE VALIDATION — inventoried types vs existing rules in DB")
    print("=" * 90)

    for csp in csps:
        inventoried = load_inventoried_types(conn, csp)
        templates   = CSP_TEMPLATES.get(csp, [])

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT from_resource_type
                FROM resource_security_relationship_rules
                WHERE csp = %s
                """,
                (csp,),
            )
            types_with_rules = {row[0] for row in cur.fetchall()}

        total   = len(inventoried)
        covered = len(inventoried & types_with_rules)
        pct     = (covered / total * 100) if total else 0.0

        print(f"\n[{csp.upper()}]  {covered}/{total} types covered  ({pct:.1f}%)  "
              f"templates_available={len(templates)}")

        uncovered = sorted(inventoried - types_with_rules)
        if uncovered:
            print(f"  Uncovered ({len(uncovered)} types):")
            for t in uncovered:
                print(f"    ✗ {t}")
        else:
            print("  All inventoried types have at least one rule.")

    print()
    print("=" * 90)
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Summary table
# ──────────────────────────────────────────────────────────────────────────────

_COL = {
    "csp":     12,
    "types":    7,
    "tmpls":   10,
    "cands":    9,
    "exist":    9,
    "insert":   9,
    "status":  10,
    "time":     8,
}


def print_summary(results: List[CSPResult], dry_run: bool, wall_s: float) -> None:
    mode = "DRY-RUN" if dry_run else "LIVE"
    w    = sum(_COL.values()) + len(_COL) - 1 + 2

    print()
    print("=" * w)
    print(f"  SECURITY RELATIONSHIP RULES GENERATOR — {mode} SUMMARY")
    print("=" * w)

    hdr = (
        f"{'CSP':<{_COL['csp']}} "
        f"{'Types':>{_COL['types']}} "
        f"{'Templates':>{_COL['tmpls']}} "
        f"{'New':>{_COL['cands']}} "
        f"{'Skipped':>{_COL['exist']}} "
        f"{'Inserted':>{_COL['insert']}} "
        f"{'Status':>{_COL['status']}} "
        f"{'Elapsed':>{_COL['time']}}"
    )
    print(hdr)
    print("-" * w)

    total_inserted = 0
    total_new      = 0
    total_skipped  = 0
    failed_csps    = []

    for r in results:
        status = "FAILED" if r.failed else ("DRY-RUN" if dry_run else "OK")
        row = (
            f"{r.csp:<{_COL['csp']}} "
            f"{r.inventoried_types:>{_COL['types']}} "
            f"{r.templates:>{_COL['tmpls']}} "
            f"{r.candidates:>{_COL['cands']}} "
            f"{r.skipped:>{_COL['exist']}} "
            f"{r.inserted:>{_COL['insert']}} "
            f"{status:>{_COL['status']}} "
            f"{r.elapsed_s:>{_COL['time'] - 1}.1f}s"
        )
        print(row)
        if r.failed:
            failed_csps.append(r.csp)
            print(f"  ERROR → {r.error}")

        total_new      += r.candidates
        total_skipped  += r.skipped
        total_inserted += r.inserted

    print("-" * w)
    print(
        f"{'TOTAL':<{_COL['csp']}} "
        f"{'':>{_COL['types']}} "
        f"{'':>{_COL['tmpls']}} "
        f"{total_new:>{_COL['cands']}} "
        f"{total_skipped:>{_COL['exist']}} "
        f"{total_inserted:>{_COL['insert']}} "
        f"{'':>{_COL['status']}} "
        f"{wall_s:>{_COL['time'] - 1}.1f}s"
    )
    print("=" * w)

    if failed_csps:
        print(f"\n  FAILED CSPs: {', '.join(failed_csps)}")
    else:
        print(f"\n  All {len(results)} CSP(s) processed successfully.")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="generate_security_relationship_rules",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print rules that would be inserted without writing to DB",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Show coverage report (inventoried types vs existing rules) and exit",
    )
    parser.add_argument(
        "--csp",
        default=",".join(sorted(CSP_TEMPLATES)),
        metavar="CSP[,CSP...]",
        help="Comma-separated list of CSPs to process (default: all)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=200,
        metavar="N",
        help="Rows per INSERT batch (default: 200)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        metavar="N",
        help="Max DB connection retry attempts (default: 3)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    return parser.parse_args()


def main() -> int:  # returns exit code
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    csps = [c.strip() for c in args.csp.split(",") if c.strip()]
    unknown = [c for c in csps if c not in CSP_TEMPLATES]
    if unknown:
        log.error(
            "Unknown CSP(s): %s  — valid values: %s",
            unknown, sorted(CSP_TEMPLATES),
        )
        return 2

    log.info(
        "Starting  csps=%s  dry_run=%s  validate=%s  batch_size=%d  retries=%d",
        csps, args.dry_run, args.validate, args.batch_size, args.retries,
    )

    # ── Connect ────────────────────────────────────────────────────────────────
    try:
        conn = connect_with_retry(max_attempts=args.retries)
    except ConnectionError as exc:
        log.error("Fatal: %s", exc)
        return 2

    try:
        # ── Schema validation ──────────────────────────────────────────────────
        try:
            validate_schema(conn)
        except RuntimeError as exc:
            log.error("Schema validation failed: %s", exc)
            return 2

        # ── Coverage-only mode ─────────────────────────────────────────────────
        if args.validate:
            run_coverage_validation(conn, csps)
            return 0

        # ── Main generation loop ───────────────────────────────────────────────
        results: List[CSPResult] = []
        wall_start = time.monotonic()

        for csp in csps:
            log.info("━━━ Processing CSP: %s ━━━", csp.upper())
            result = process_csp(conn, csp, args.dry_run, args.batch_size)
            results.append(result)
            log.info(
                "[%s] Done — inserted=%d  skipped=%d  failed=%s  elapsed=%.1fs",
                csp.upper(), result.inserted, result.skipped, result.failed, result.elapsed_s,
            )

        wall_elapsed = time.monotonic() - wall_start
        print_summary(results, args.dry_run, wall_elapsed)

        # ── Exit code ──────────────────────────────────────────────────────────
        failed = [r for r in results if r.failed]
        if not failed:
            return 0
        if len(failed) == len(results):
            return 2   # every CSP failed
        return 1       # partial failure

    finally:
        conn.close()
        log.info("DB connection closed.")


if __name__ == "__main__":
    sys.exit(main())
