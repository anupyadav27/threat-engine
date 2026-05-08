#!/usr/bin/env python3
"""
generate_ciem_field_catalog.py — Build the CIEM log field catalog for the user-facing rule builder.

Outputs two JSON files:
  1. ciem_field_catalog.json   — per source_type field definitions (type, operators, format hints)
  2. ciem_operation_catalog.json — per source_type, all service+operation pairs with human labels

The catalog drives the UI rule builder so users never have to guess:
  - "IAM" vs "iam" vs "Identity and Access Management"
  - "SetIamPolicy" vs "set_iam_policy" vs "iam.googleapis.com"
  - "iam-identity.user-apikey.create" vs just "create"

Usage:
    python3 generate_ciem_field_catalog.py [--out-dir catalog/rule/]
    python3 generate_ciem_field_catalog.py --db  # also writes to DB (ciem_log_field_catalog)
"""

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent

CIEM_DIRS = {
    "aws":   ROOT / "catalog" / "rule" / "aws_rule_ciem",
    "azure": ROOT / "catalog" / "rule" / "azure_rule_ciem",
    "gcp":   ROOT / "catalog" / "rule" / "gcp_rule_ciem",
    "oci":   ROOT / "catalog" / "rule" / "oci_rule_ciem",
    "ibm":   ROOT / "catalog" / "rule" / "ibm_rule_ciem",
    "k8s":   ROOT / "catalog" / "rule" / "k8s_rule_ciem",
}

OUT_DIR = ROOT / "catalog" / "rule"


# ─────────────────────────────────────────────────────────────────────────────
# Human-readable labels for services (exact parser output → display label)
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_LABELS: Dict[str, Dict[str, str]] = {
    "cloudtrail": {
        "access-analyzer": "Access Analyzer",
        "acm": "ACM (Certificate Manager)",
        "apigateway": "API Gateway",
        "athena": "Athena",
        "batch": "Batch",
        "cloudformation": "CloudFormation",
        "cloudfront": "CloudFront",
        "cloudtrail": "CloudTrail",
        "codebuild": "CodeBuild",
        "codedeploy": "CodeDeploy",
        "codepipeline": "CodePipeline",
        "cognito-identity": "Cognito Identity",
        "cognito-idp": "Cognito User Pools (IDP)",
        "config": "AWS Config",
        "dynamodb": "DynamoDB",
        "ec2": "EC2 (Elastic Compute Cloud)",
        "ecr": "ECR (Container Registry)",
        "ecs": "ECS (Container Service)",
        "eks": "EKS (Kubernetes Service)",
        "elasticache": "ElastiCache",
        "elasticfilesystem": "EFS (Elastic File System)",
        "elasticloadbalancing": "ELB (Load Balancing)",
        "events": "EventBridge",
        "glue": "Glue",
        "guardduty": "GuardDuty",
        "iam": "IAM (Identity & Access Management)",
        "inspector2": "Inspector",
        "kms": "KMS (Key Management Service)",
        "lambda": "Lambda",
        "lightsail": "Lightsail",
        "logs": "CloudWatch Logs",
        "macie2": "Macie",
        "monitoring": "CloudWatch",
        "network-firewall": "Network Firewall",
        "organizations": "Organizations",
        "rds": "RDS (Relational Database Service)",
        "redshift": "Redshift",
        "route53": "Route 53",
        "s3": "S3 (Simple Storage Service)",
        "secretsmanager": "Secrets Manager",
        "securityhub": "Security Hub",
        "ses": "SES (Email Service)",
        "sns": "SNS (Simple Notification Service)",
        "sqs": "SQS (Simple Queue Service)",
        "ssm": "SSM (Systems Manager)",
        "sso": "SSO (Single Sign-On)",
        "states": "Step Functions",
        "sts": "STS (Security Token Service)",
        "wafv2": "WAF v2 (Web Application Firewall)",
    },
    "azure_activity": {
        # Azure: service is the lowercase operationName provider, e.g. "compute"
        "compute": "Compute (Virtual Machines)",
        "storage": "Storage Accounts",
        "authorization": "Authorization / RBAC",
        "network": "Virtual Network",
        "keyvault": "Key Vault",
        "containerservice": "AKS (Container Service)",
        "containerregistry": "Container Registry",
        "sql": "SQL Database",
        "documentdb": "Cosmos DB",
        "web": "App Service",
        "appcontainers": "Container Apps",
        "apimanagement": "API Management",
        "logic": "Logic Apps",
        "datafactory": "Data Factory",
        "insights": "Azure Monitor / Application Insights",
        "operationalinsights": "Log Analytics",
        "security": "Microsoft Defender",
        "app": "Container Apps (Managed Environments)",
        "dbformysql": "MySQL Database",
        "dbforpostgresql": "PostgreSQL Database",
        "cognitiveservices": "Cognitive Services / AI",
        "servicebus": "Service Bus",
        "eventhub": "Event Hubs",
        "devtestlab": "Dev/Test Labs",
        "hdinsight": "HDInsight",
        "cache": "Azure Cache for Redis",
        "batch": "Azure Batch",
        "cdn": "CDN",
        "dns": "DNS",
        "monitor": "Azure Monitor",
        "resources": "Resource Manager",
        "policyinsights": "Azure Policy",
        "blueprint": "Azure Blueprints",
    },
    "gcp_audit": {
        "iam.googleapis.com": "IAM (Identity & Access Management)",
        "compute.googleapis.com": "Compute Engine",
        "storage.googleapis.com": "Cloud Storage",
        "container.googleapis.com": "GKE (Kubernetes Engine)",
        "cloudkms.googleapis.com": "Cloud KMS",
        "secretmanager.googleapis.com": "Secret Manager",
        "cloudresourcemanager.googleapis.com": "Resource Manager",
        "cloudsql.googleapis.com": "Cloud SQL",
        "sqladmin.googleapis.com": "Cloud SQL Admin",
        "bigquery.googleapis.com": "BigQuery",
        "dns.googleapis.com": "Cloud DNS",
        "logging.googleapis.com": "Cloud Logging",
        "monitoring.googleapis.com": "Cloud Monitoring",
        "pubsub.googleapis.com": "Pub/Sub",
        "run.googleapis.com": "Cloud Run",
        "cloudfunctions.googleapis.com": "Cloud Functions",
        "cloudbuild.googleapis.com": "Cloud Build",
        "artifactregistry.googleapis.com": "Artifact Registry",
        "binaryauthorization.googleapis.com": "Binary Authorization",
        "accesscontextmanager.googleapis.com": "Access Context Manager (VPC-SC)",
        "accessapproval.googleapis.com": "Access Approval",
        "iamcredentials.googleapis.com": "IAM Credentials",
        "identitytoolkit.googleapis.com": "Identity Toolkit (Firebase Auth)",
        "orgpolicy.googleapis.com": "Organization Policy",
        "securitycenter.googleapis.com": "Security Command Center",
    },
    "oci_audit": {
        "com.oraclecloud.identitycontrolplane": "IAM (Identity Control Plane)",
        "com.oraclecloud.computemanagement": "Compute",
        "com.oraclecloud.objectstorage": "Object Storage",
        "com.oraclecloud.database": "Database Service",
        "com.oraclecloud.networking": "Virtual Cloud Network (VCN)",
        "com.oraclecloud.vault": "Vault (Key Management)",
        "com.oraclecloud.containerengine": "OKE (Container Engine for Kubernetes)",
        "com.oraclecloud.cloudguard": "Cloud Guard",
        "com.oraclecloud.logging": "Logging",
        "com.oraclecloud.resourcemanager": "Resource Manager",
        "com.oraclecloud.audit": "Audit Service",
        "com.oraclecloud.waf": "WAF (Web Application Firewall)",
    },
    "ibm_activity": {
        # IBM: service is first segment of CADF action, hyphens→underscores
        "iam_identity": "IAM Identity",
        "cloud_object_storage": "Cloud Object Storage (COS)",
        "is": "VPC / Virtual Server Instances",
        "containers_kubernetes": "IKS (Kubernetes Service)",
        "databases_for_postgresql": "Databases for PostgreSQL",
        "databases_for_mongodb": "Databases for MongoDB",
        "databases_for_redis": "Databases for Redis",
        "kms": "Key Protect / Key Management",
        "security_compliance_center": "Security & Compliance Center",
        "logdna": "IBM Log Analysis",
        "secrets_manager": "Secrets Manager",
    },
    "eks_audit": {},  # EKS has no "service" field — only verb-based operations
    "k8s_audit": {},
}

# ─────────────────────────────────────────────────────────────────────────────
# Field definitions per source_type (operators, types, descriptions)
# ─────────────────────────────────────────────────────────────────────────────

# Valid operators from rule_evaluator.py _single_condition()
STRING_OPS = ["equals", "not_equals", "in", "contains", "starts_with", "starts_with_any"]
ENUM_OPS   = ["equals", "not_equals", "in"]

# Shared fields across all audit log source types
_COMMON_AUDIT_FIELDS = {
    "outcome": {
        "display_name": "Outcome / Result",
        "field_type": "enum",
        "operators": ENUM_OPS,
        "description": "Whether the API call succeeded or failed",
        "format_hint": "Lowercase: 'success' or 'failure'",
        "enum_values": [
            {"value": "success", "label": "Success"},
            {"value": "failure", "label": "Failure"},
            {"value": "unknown", "label": "Unknown"},
        ],
    },
    "actor.principal": {
        "display_name": "Actor / User Identity",
        "field_type": "string",
        "operators": STRING_OPS,
        "description": "The identity that performed the action (user ARN, email, service account, etc.)",
        "format_hint": "Exact match is case-sensitive. Use 'contains' for partial matching.",
        "examples": {
            "cloudtrail": "arn:aws:iam::123456789012:user/admin",
            "azure_activity": "admin@company.com",
            "gcp_audit": "user@project.iam.gserviceaccount.com",
            "oci_audit": "ocid1.user.oc1..aaaaa...",
            "ibm_activity": "IBMid-1234567890",
        },
    },
    "actor.ip_address": {
        "display_name": "Actor IP Address",
        "field_type": "string",
        "operators": STRING_OPS,
        "description": "Source IP address of the actor",
        "format_hint": "IPv4 or IPv6. Use 'starts_with' for CIDR-like matching (e.g. '10.0.').",
    },
    "actor.principal_type": {
        "display_name": "Actor Type",
        "field_type": "string",
        "operators": ENUM_OPS,
        "description": "Type of identity (user, role, service account, etc.)",
    },
    "actor.account_id": {
        "display_name": "Actor Account / Project ID",
        "field_type": "string",
        "operators": ENUM_OPS,
        "description": "Cloud account or project ID of the actor",
    },
    "resource.uid": {
        "display_name": "Resource ID / ARN",
        "field_type": "string",
        "operators": STRING_OPS,
        "description": "Unique identifier of the resource being accessed",
    },
    "resource.type": {
        "display_name": "Resource Type",
        "field_type": "string",
        "operators": STRING_OPS,
        "description": "Type/category of the resource (e.g. 'AWS::IAM::User', 'pods')",
    },
    "resource.name": {
        "display_name": "Resource Name",
        "field_type": "string",
        "operators": STRING_OPS,
        "description": "Name of the specific resource",
    },
    "resource.region": {
        "display_name": "Resource Region",
        "field_type": "string",
        "operators": ENUM_OPS,
        "description": "Cloud region where the resource resides",
    },
    "error_code": {
        "display_name": "Error Code",
        "field_type": "string",
        "operators": ENUM_OPS,
        "description": "Error code when the operation failed (e.g. 'AccessDenied', 'Throttling')",
        "examples": {
            "cloudtrail": ["AccessDenied", "Throttling", "UnauthorizedOperation"],
        },
    },
}

# Per-source_type field catalog
SOURCE_TYPE_CATALOG: Dict[str, Dict[str, Any]] = {
    "cloudtrail": {
        "display_name": "AWS CloudTrail",
        "provider": "aws",
        "description": "AWS API call history — records every AWS Management Console action and API call",
        "doc_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html",
        "log_format": "JSON (Records array)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "cloudtrail",
                "description": "Always 'cloudtrail' for CloudTrail rules",
            },
            "service": {
                "display_name": "AWS Service",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "The AWS service that received the API call",
                "format_hint": (
                    "ALWAYS lowercase, NEVER with .amazonaws.com suffix. "
                    "Parser strips domain automatically. "
                    "Use 'iam' NOT 'IAM', 'Identity and Access Management', or 'iam.amazonaws.com'."
                ),
            },
            "operation": {
                "display_name": "API Operation (Event Name)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "The specific API action — maps to CloudTrail eventName",
                "format_hint": (
                    "PascalCase, exactly as CloudTrail records it. "
                    "Use 'CreateUser' NOT 'createuser', 'create_user', or 'Create User'."
                ),
            },
            **_COMMON_AUDIT_FIELDS,
        },
    },

    "azure_activity": {
        "display_name": "Azure Activity Log",
        "provider": "azure",
        "description": "Azure Resource Manager operations — records all ARM API calls across subscriptions",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
        "log_format": "JSON (records array or JSON-lines)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "azure_activity",
                "description": "Always 'azure_activity' for Azure Activity Log rules",
            },
            "service": {
                "display_name": "Azure Service / Provider",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "Azure resource provider extracted from operationName",
                "format_hint": (
                    "Lowercase, Microsoft. prefix removed. "
                    "Parser extracts 'compute' from 'Microsoft.Compute/virtualMachines/write'. "
                    "Use 'compute' NOT 'Microsoft.Compute' or 'Compute'."
                ),
            },
            "operation": {
                "display_name": "ARM Operation",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Full Azure ARM operationName (e.g. Microsoft.Authorization/roleAssignments/write)",
                "format_hint": (
                    "Full ARM path with Microsoft. prefix, case-sensitive. "
                    "Use 'Microsoft.Authorization/roleAssignments/write' NOT 'AssignRole'. "
                    "Use 'starts_with' to match all operations of a resource type."
                ),
            },
            **_COMMON_AUDIT_FIELDS,
        },
    },

    "gcp_audit": {
        "display_name": "GCP Cloud Audit Logs",
        "provider": "gcp",
        "description": "GCP Admin Activity and Data Access logs via Cloud Logging (protoPayload format)",
        "doc_url": "https://cloud.google.com/logging/docs/audit/understanding-audit-logs",
        "log_format": "JSON (protoPayload envelope, array or JSON-lines)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "gcp_audit",
                "description": "Always 'gcp_audit' for GCP audit log rules",
            },
            "service": {
                "display_name": "GCP Service (serviceName)",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "GCP service name from protoPayload.serviceName",
                "format_hint": (
                    "Full googleapis.com name — NOT shortened. "
                    "Use 'iam.googleapis.com' NOT 'iam', 'IAM', or 'Identity and Access Management'. "
                    "Use 'compute.googleapis.com' NOT 'Compute Engine' or 'gce'."
                ),
            },
            "operation": {
                "display_name": "GCP API Method (methodName)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Full gRPC method name from protoPayload.methodName",
                "format_hint": (
                    "Full gRPC path — case-sensitive. "
                    "Use 'google.iam.v1.IAMPolicy.SetIamPolicy' NOT 'SetIamPolicy' or 'set_iam_policy'. "
                    "Use 'contains' to match short names like 'SetIamPolicy' across all services."
                ),
            },
            **_COMMON_AUDIT_FIELDS,
        },
    },

    "oci_audit": {
        "display_name": "OCI Audit Log",
        "provider": "oci",
        "description": "OCI Audit logs — records all OCI API calls via data.eventType",
        "doc_url": "https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/overview.htm",
        "log_format": "JSON (data envelope or JSON-lines)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "oci_audit",
                "description": "Always 'oci_audit' for OCI audit rules",
            },
            "service": {
                "display_name": "OCI Service Namespace",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "OCI service namespace extracted from data.eventType (all segments except last)",
                "format_hint": (
                    "Reversed-domain format, all lowercase. "
                    "Parser splits 'com.oraclecloud.identitycontrolplane.CreateUser' → "
                    "service='com.oraclecloud.identitycontrolplane', operation='CreateUser'. "
                    "Use 'com.oraclecloud.identitycontrolplane' NOT 'IAM' or 'identity'."
                ),
            },
            "operation": {
                "display_name": "OCI Operation (eventType suffix)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Last segment of OCI eventType (the operation name, PascalCase)",
                "format_hint": (
                    "PascalCase, last segment of eventType. "
                    "Parser extracts 'CreateUser' from 'com.oraclecloud.identitycontrolplane.CreateUser'. "
                    "Use 'CreateUser' NOT 'createuser' or 'create_user'."
                ),
            },
            **_COMMON_AUDIT_FIELDS,
        },
    },

    "ibm_activity": {
        "display_name": "IBM Cloud Activity Tracker (CADF)",
        "provider": "ibm",
        "description": "IBM Cloud audit logs in CADF format — records all IBM Cloud API calls",
        "doc_url": "https://cloud.ibm.com/docs/activity-tracker",
        "log_format": "JSON (CADF format — action, outcome, initiator, target)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "ibm_activity",
                "description": "Always 'ibm_activity' for IBM Activity Tracker rules",
            },
            "service": {
                "display_name": "IBM Service (CADF action prefix)",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "First segment of CADF action string, hyphens replaced with underscores",
                "format_hint": (
                    "Lowercase with underscores. "
                    "Parser extracts 'iam_identity' from 'iam-identity.user-apikey.create'. "
                    "Use 'iam_identity' NOT 'IAM', 'iam-identity', or 'Identity and Access Management'."
                ),
            },
            "operation": {
                "display_name": "IBM API Action (full CADF action)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Full IBM CADF action string (service.resource.verb format)",
                "format_hint": (
                    "Full CADF action string with hyphens and dots — case-sensitive. "
                    "Use 'iam-identity.user-apikey.create' NOT 'create' or 'CreateApiKey'. "
                    "Use 'contains' or 'starts_with' for broader matches."
                ),
            },
            **_COMMON_AUDIT_FIELDS,
        },
    },

    "eks_audit": {
        "display_name": "AWS EKS Kubernetes Audit Log",
        "provider": "aws",
        "description": "K8s API server audit events from AWS EKS, delivered via CloudWatch",
        "doc_url": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
        "log_format": "JSON (CloudWatch batch of K8s audit events)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "eks_audit",
                "description": "Always 'eks_audit' for EKS audit rules",
            },
            "operation": {
                "display_name": "K8s Verb (HTTP Method)",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "Kubernetes API verb — maps to objectRef HTTP verb",
                "format_hint": "Always lowercase. Read-only (get/list/watch) are filtered out by parser.",
                "enum_values": [
                    {"value": "create",   "label": "Create"},
                    {"value": "delete",   "label": "Delete"},
                    {"value": "update",   "label": "Update"},
                    {"value": "patch",    "label": "Patch"},
                    {"value": "bind",     "label": "Bind (RBAC)"},
                    {"value": "escalate", "label": "Escalate (RBAC privilege escalation)"},
                    {"value": "exec",     "label": "Exec (pod exec)"},
                    {"value": "impersonate", "label": "Impersonate"},
                ],
            },
            "resource.type": {
                "display_name": "K8s Resource Kind",
                "field_type": "string",
                "operators": ENUM_OPS,
                "description": "Kubernetes resource type (objectRef.resource)",
                "format_hint": "Lowercase plural. Use 'pods', 'secrets', 'configmaps', 'roles', 'clusterroles'.",
                "examples": ["pods", "secrets", "configmaps", "serviceaccounts", "roles",
                             "clusterroles", "rolebindings", "clusterrolebindings",
                             "persistentvolumes", "namespaces", "nodes"],
            },
            "actor.principal": {
                "display_name": "Actor (Kubernetes User / ServiceAccount)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Username from K8s user object",
                "examples": [
                    "system:serviceaccount:kube-system:deployment-controller",
                    "system:anonymous",
                    "kubernetes-admin",
                ],
            },
            "actor.ip_address": {
                "display_name": "Actor IP Address",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Source IP of the API caller",
            },
            "resource.name": {
                "display_name": "Resource Name",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Name of the specific K8s object",
            },
            "outcome": {
                "display_name": "HTTP Response Code",
                "field_type": "string",
                "operators": ["equals", "not_equals", "starts_with"],
                "description": "HTTP status code from responseStatus (as string)",
                "format_hint": "String representation of HTTP status code. Use 'starts_with' for ranges: '2' for 2xx, '4' for 4xx.",
                "examples": ["200", "201", "403", "404"],
            },
        },
    },

    "k8s_audit": {
        "display_name": "Generic Kubernetes Audit Log",
        "provider": "k8s",
        "description": "Self-managed K8s API server audit events",
        "doc_url": "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
        "log_format": "JSON (K8s audit policy events)",
        "fields": {
            "source_type": {
                "display_name": "Log Source Type",
                "field_type": "fixed",
                "operators": ["equals"],
                "fixed_value": "k8s_audit",
                "description": "Always 'k8s_audit' for self-managed K8s rules",
            },
            "operation": {
                "display_name": "K8s Verb",
                "field_type": "enum",
                "operators": ENUM_OPS,
                "description": "Kubernetes API verb",
                "format_hint": "Always lowercase: 'create', 'delete', 'update', 'patch'.",
                "enum_values": [
                    {"value": "create",   "label": "Create"},
                    {"value": "delete",   "label": "Delete"},
                    {"value": "update",   "label": "Update"},
                    {"value": "patch",    "label": "Patch"},
                    {"value": "bind",     "label": "Bind"},
                    {"value": "escalate", "label": "Escalate"},
                    {"value": "exec",     "label": "Exec (pod exec)"},
                ],
            },
            "resource.type": {
                "display_name": "K8s Resource Kind",
                "field_type": "string",
                "operators": ENUM_OPS,
                "description": "Kubernetes resource type (objectRef.resource), lowercase plural",
                "examples": ["pods", "secrets", "configmaps", "roles", "clusterroles",
                             "rolebindings", "clusterrolebindings", "serviceaccounts"],
            },
            "actor.principal": {
                "display_name": "Actor (K8s Username)",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Kubernetes username",
            },
            "actor.ip_address": {
                "display_name": "Actor IP Address",
                "field_type": "string",
                "operators": STRING_OPS,
                "description": "Source IP of the API caller",
            },
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Helper: convert PascalCase/camelCase → "Title Words"
# ─────────────────────────────────────────────────────────────────────────────

def _pascal_to_words(name: str) -> str:
    """CreateUserAccessKey → 'Create User Access Key'"""
    # Insert space before each uppercase letter that follows a lowercase letter or number
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    # Insert space before uppercase sequences followed by lowercase (e.g. ARNs → "AR Ns" → fix)
    spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", spaced)
    return spaced.strip()


def _arm_op_label(arm_op: str) -> str:
    """Microsoft.Authorization/roleAssignments/write → 'Authorization: Write Role Assignment'"""
    # Remove Microsoft. prefix
    clean = arm_op.replace("Microsoft.", "")
    parts = clean.split("/")
    if len(parts) >= 2:
        provider = parts[0]
        # Get verb (last part)
        verb_map = {
            "write": "Create / Update",
            "delete": "Delete",
            "read": "Read",
            "action": "Execute",
            "listkeys": "List Keys",
            "start": "Start",
            "stop": "Stop",
            "restart": "Restart",
        }
        verb = verb_map.get(parts[-1].lower(), parts[-1].title())
        resource = " ".join(p.rstrip("s").title() for p in parts[1:-1]) if len(parts) > 2 else parts[1].title()
        return f"{provider}: {verb} {resource}"
    return clean.replace("/", " → ")


def _gcp_op_label(method: str) -> str:
    """google.iam.v1.IAMPolicy.SetIamPolicy → 'Set IAM Policy'"""
    # Take last dot-segment
    last = method.rsplit(".", 1)[-1]
    return _pascal_to_words(last)


def _cadf_op_label(action: str) -> str:
    """iam-identity.user-apikey.create → 'Create IAM User API Key'"""
    parts = action.split(".")
    verb_map = {
        "create": "Create",
        "delete": "Delete",
        "update": "Update",
        "read": "Read",
        "list": "List",
        "enable": "Enable",
        "disable": "Disable",
        "rotate": "Rotate",
    }
    verb = verb_map.get(parts[-1].lower(), parts[-1].title()) if parts else ""
    # Build resource description from middle segments
    resource_parts = [p.replace("-", " ").title() for p in parts[:-1]]
    return f"{verb} {' '.join(resource_parts)}".strip()


# ─────────────────────────────────────────────────────────────────────────────
# Extract values from CIEM YAML files
# ─────────────────────────────────────────────────────────────────────────────

def flatten_conds(conds: Any) -> List[Dict]:
    """Flatten nested condition structures to a flat list."""
    if isinstance(conds, dict):
        if "all" in conds:
            return conds["all"]
        if "field" in conds:
            return [conds]
    return []


def extract_values_from_yamls() -> Dict[str, Dict[str, Any]]:
    """
    Read all CIEM YAMLs and extract:
      - per source_type: set of service values
      - per source_type+service: set of operation values

    Returns:
        Dict mapping source_type → {"services": dict[value→label], "ops": dict[svc→set[op]]}
    """
    catalog: Dict[str, Dict] = {}

    for provider, ciem_dir in CIEM_DIRS.items():
        if not ciem_dir.exists():
            continue

        # Default source_type per provider when not in conditions
        default_st = {
            "aws": "cloudtrail",
            "azure": "azure_activity",
        }.get(provider)

        for p in sorted(ciem_dir.rglob("*.yaml")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            cfg = data.get("check_config", {})
            if not cfg:
                continue

            # Collect all conditions (simple + correlation event sub-conditions)
            all_conds = flatten_conds(cfg.get("conditions", {}))
            for ev in cfg.get("events", []):
                all_conds += flatten_conds(ev.get("conditions", {}))

            # Determine source_type
            st_cond = next(
                (c.get("value") for c in all_conds
                 if c.get("field") == "source_type" and isinstance(c.get("value"), str)),
                default_st,
            )
            if not st_cond:
                continue

            if st_cond not in catalog:
                catalog[st_cond] = {
                    "services": {},
                    "ops": collections.defaultdict(set),
                    "raw_fields": set(),
                }

            # Collect service and operation values
            svc_val = next(
                (c.get("value") for c in all_conds
                 if c.get("field") == "service" and isinstance(c.get("value"), str)),
                None,
            )
            op_val = next(
                (c.get("value") for c in all_conds
                 if c.get("field") == "operation" and isinstance(c.get("value"), str)),
                None,
            )

            if svc_val:
                catalog[st_cond]["services"][svc_val] = True
            if op_val:
                svc_key = svc_val or "__other__"
                catalog[st_cond]["ops"][svc_key].add(op_val)

            for c in all_conds:
                if isinstance(c.get("field"), str):
                    catalog[st_cond]["raw_fields"].add(c["field"])

    return catalog


# ─────────────────────────────────────────────────────────────────────────────
# Build operation catalog with labels
# ─────────────────────────────────────────────────────────────────────────────

def build_operation_catalog(extracted: Dict) -> Dict[str, Any]:
    """
    Build the operation catalog: for each source_type, list all service+operation
    pairs with human-readable display labels.
    """
    result: Dict[str, Any] = {}

    for source_type, data in extracted.items():
        svc_labels = SERVICE_LABELS.get(source_type, {})

        # Build service list
        services = []
        for svc_val in sorted(data["services"].keys()):
            svc_label = svc_labels.get(svc_val, svc_val.replace("-", " ").replace("_", " ").title())
            ops = sorted(data["ops"].get(svc_val, set()))
            op_entries = []
            for op in ops:
                if source_type == "cloudtrail":
                    op_label = _pascal_to_words(op)
                elif source_type == "azure_activity":
                    op_label = _arm_op_label(op)
                elif source_type == "gcp_audit":
                    op_label = _gcp_op_label(op)
                elif source_type == "oci_audit":
                    op_label = _pascal_to_words(op)
                elif source_type == "ibm_activity":
                    op_label = _cadf_op_label(op)
                else:
                    op_label = op
                op_entries.append({"value": op, "label": op_label})

            services.append({
                "value": svc_val,
                "label": svc_label,
                "operations": op_entries,
            })

        # Also collect "other" operations (no service extracted)
        other_ops = sorted(data["ops"].get("__other__", set()))
        ungrouped_ops = []
        for op in other_ops:
            if source_type == "eks_audit" or source_type == "k8s_audit":
                op_label = op.title()
            elif source_type == "azure_activity":
                op_label = _arm_op_label(op)
            elif source_type == "gcp_audit":
                op_label = _gcp_op_label(op)
            elif source_type == "ibm_activity":
                op_label = _cadf_op_label(op)
            else:
                op_label = _pascal_to_words(op)
            ungrouped_ops.append({"value": op, "label": op_label})

        result[source_type] = {
            "services": services,
            "ungrouped_operations": ungrouped_ops,
            "total_services": len(services),
            "total_operations": sum(len(s["operations"]) for s in services) + len(ungrouped_ops),
        }

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Build the full field catalog (field definitions + operation value lists merged)
# ─────────────────────────────────────────────────────────────────────────────

def build_field_catalog(extracted: Dict, op_catalog: Dict) -> Dict[str, Any]:
    """
    Merge static field definitions with extracted service/operation values.
    """
    result: Dict[str, Any] = {}

    for source_type, static in SOURCE_TYPE_CATALOG.items():
        entry = {
            "display_name": static["display_name"],
            "provider": static["provider"],
            "description": static["description"],
            "doc_url": static.get("doc_url", ""),
            "log_format": static.get("log_format", ""),
            "fields": {},
        }

        svc_labels = SERVICE_LABELS.get(source_type, {})
        extracted_st = extracted.get(source_type, {})
        op_st = op_catalog.get(source_type, {})

        for field_name, field_def in static["fields"].items():
            fd = dict(field_def)

            # Inject service enum values from extracted YAML data
            if field_name == "service" and extracted_st.get("services"):
                enum_vals = []
                for svc_val in sorted(extracted_st["services"].keys()):
                    svc_label = svc_labels.get(
                        svc_val,
                        svc_val.replace("-", " ").replace("_", " ").title()
                    )
                    enum_vals.append({"value": svc_val, "label": svc_label})
                fd["enum_values"] = enum_vals

            # Inject operation values grouped by service
            if field_name == "operation":
                fd["values_by_service"] = [
                    {
                        "service_value": svc["value"],
                        "service_label": svc["label"],
                        "operations": svc["operations"],
                    }
                    for svc in op_st.get("services", [])
                ]
                fd["ungrouped_values"] = op_st.get("ungrouped_operations", [])
                fd["total_count"] = op_st.get("total_operations", 0)

            entry["fields"][field_name] = fd

        result[source_type] = entry

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Write catalog to DB (optional)
# ─────────────────────────────────────────────────────────────────────────────

def write_to_db(field_catalog: Dict, op_catalog: Dict) -> None:
    """Write catalog to ciem_log_field_catalog and ciem_operation_catalog tables."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        print("psycopg2 not available — skipping DB write")
        return

    conn_params = dict(
        host     = os.getenv("CHECK_DB_HOST", "localhost"),
        port     = int(os.getenv("CHECK_DB_PORT", "5432")),
        dbname   = os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user     = os.getenv("CHECK_DB_USER", "postgres"),
        password = os.getenv("CHECK_DB_PASSWORD", ""),
    )

    try:
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = False
    except Exception as e:
        print(f"Cannot connect to DB: {e}")
        return

    try:
        with conn.cursor() as cur:
            # Ensure tables exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ciem_log_field_catalog (
                    source_type     VARCHAR(64)  NOT NULL,
                    field_name      VARCHAR(128) NOT NULL,
                    display_name    VARCHAR(256) NOT NULL,
                    field_type      VARCHAR(32)  NOT NULL,
                    operators       JSONB        NOT NULL DEFAULT '[]',
                    description     TEXT,
                    format_hint     TEXT,
                    enum_values     JSONB,
                    examples        JSONB,
                    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (source_type, field_name)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ciem_operation_catalog (
                    source_type     VARCHAR(64)  NOT NULL,
                    service_value   VARCHAR(256),
                    service_label   VARCHAR(256),
                    operation_value VARCHAR(512) NOT NULL,
                    operation_label VARCHAR(512) NOT NULL,
                    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (source_type, operation_value)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ciem_source_type_catalog (
                    source_type     VARCHAR(64)  PRIMARY KEY,
                    display_name    VARCHAR(256) NOT NULL,
                    provider        VARCHAR(32)  NOT NULL,
                    description     TEXT,
                    doc_url         VARCHAR(512),
                    log_format      VARCHAR(128),
                    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
                )
            """)

            # Upsert source types
            for st, data in field_catalog.items():
                cur.execute("""
                    INSERT INTO ciem_source_type_catalog
                        (source_type, display_name, provider, description, doc_url, log_format)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_type) DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        provider     = EXCLUDED.provider,
                        description  = EXCLUDED.description,
                        doc_url      = EXCLUDED.doc_url,
                        log_format   = EXCLUDED.log_format,
                        updated_at   = NOW()
                """, (st, data["display_name"], data["provider"],
                      data["description"], data.get("doc_url"), data.get("log_format")))

            # Upsert fields
            field_rows = []
            for st, data in field_catalog.items():
                for fn, fd in data["fields"].items():
                    field_rows.append((
                        st, fn,
                        fd.get("display_name", fn),
                        fd.get("field_type", "string"),
                        psycopg2.extras.Json(fd.get("operators", [])),
                        fd.get("description"),
                        fd.get("format_hint"),
                        psycopg2.extras.Json(fd.get("enum_values")),
                        psycopg2.extras.Json(fd.get("examples")),
                    ))

            cur.executemany("""
                INSERT INTO ciem_log_field_catalog
                    (source_type, field_name, display_name, field_type, operators,
                     description, format_hint, enum_values, examples)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_type, field_name) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    field_type   = EXCLUDED.field_type,
                    operators    = EXCLUDED.operators,
                    description  = EXCLUDED.description,
                    format_hint  = EXCLUDED.format_hint,
                    enum_values  = EXCLUDED.enum_values,
                    examples     = EXCLUDED.examples,
                    updated_at   = NOW()
            """, field_rows)

            # Upsert operations
            op_rows = []
            for st, data in op_catalog.items():
                for svc in data.get("services", []):
                    for op in svc["operations"]:
                        op_rows.append((
                            st, svc["value"], svc["label"],
                            op["value"], op["label"],
                        ))
                for op in data.get("ungrouped_operations", []):
                    op_rows.append((st, None, None, op["value"], op["label"]))

            if op_rows:
                cur.executemany("""
                    INSERT INTO ciem_operation_catalog
                        (source_type, service_value, service_label, operation_value, operation_label)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (source_type, operation_value) DO UPDATE SET
                        service_value   = EXCLUDED.service_value,
                        service_label   = EXCLUDED.service_label,
                        operation_label = EXCLUDED.operation_label,
                        updated_at      = NOW()
                """, op_rows)

        conn.commit()
        print(f"  DB: wrote {len(field_catalog)} source types, "
              f"{sum(len(d['fields']) for d in field_catalog.values())} fields, "
              f"{sum(r.get('total_operations', 0) for r in op_catalog.values())} operations")

    except Exception as e:
        conn.rollback()
        print(f"DB write failed: {e}")
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Generate CIEM log field catalog JSON files."""
    p = argparse.ArgumentParser(description="Generate CIEM log field catalog")
    p.add_argument("--out-dir", default=str(OUT_DIR), help="Output directory for JSON files")
    p.add_argument("--db", action="store_true", help="Also write catalog to database")
    p.add_argument("--dry-run", action="store_true", help="Print summary only, don't write files")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Extracting service/operation values from CIEM YAMLs...")
    extracted = extract_values_from_yamls()

    for st, v in sorted(extracted.items()):
        print(f"  {st}: {len(v['services'])} services, "
              f"{sum(len(ops) for ops in v['ops'].values())} operations")

    print("\nBuilding operation catalog...")
    op_catalog = build_operation_catalog(extracted)

    print("Building field catalog...")
    field_catalog = build_field_catalog(extracted, op_catalog)

    if args.dry_run:
        print("\n[DRY RUN] Would write:")
        print(f"  {out_dir}/ciem_field_catalog.json")
        print(f"  {out_dir}/ciem_operation_catalog.json")
        for st, data in sorted(field_catalog.items()):
            print(f"  {st}: {len(data['fields'])} fields, "
                  f"{op_catalog.get(st, {}).get('total_operations', 0)} operations")
        return

    # Write field catalog
    fc_path = out_dir / "ciem_field_catalog.json"
    fc_path.write_text(json.dumps(field_catalog, indent=2, ensure_ascii=False))
    print(f"\nWrote: {fc_path}")

    # Write operation catalog
    oc_path = out_dir / "ciem_operation_catalog.json"
    oc_path.write_text(json.dumps(op_catalog, indent=2, ensure_ascii=False))
    print(f"Wrote: {oc_path}")

    total_ops = sum(d.get("total_operations", 0) for d in op_catalog.values())
    total_svcs = sum(d.get("total_services", 0) for d in op_catalog.values())
    total_fields = sum(len(d["fields"]) for d in field_catalog.values())
    print(f"\nCatalog summary:")
    print(f"  {len(field_catalog)} source types")
    print(f"  {total_fields} total field definitions")
    print(f"  {total_svcs} services across all source types")
    print(f"  {total_ops} operations across all source types")

    if args.db:
        print("\nWriting to database...")
        write_to_db(field_catalog, op_catalog)

    print("\nDone.")


if __name__ == "__main__":
    main()
