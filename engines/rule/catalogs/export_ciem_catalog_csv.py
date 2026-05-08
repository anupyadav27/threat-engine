#!/usr/bin/env python3
"""
export_ciem_catalog_csv.py — Single unified CIEM log rule field catalog CSV.

Each row = one (source_type, log_field, field_value, rule) combination.
Mirrors the style of catalog/discovery_generator/oci/oci_field_rule_catalog.csv
but for CIEM log-detection rules instead of posture check rules.

Columns:
  csp, source_type, source_type_label,
  log_field, field_label, field_type, operators, format_hint,
  field_value, field_value_label,
  rule_id, rule_title, rule_severity, rule_threat_category,
  rule_condition_op, rule_conditions_summary, rule_conditions_json,
  rule_file

Reads: catalog/rule/{aws,azure,gcp,oci,ibm,k8s}_rule_ciem/**/*.yaml
Writes: engines/rule/catalogs/ciem_log_rule_field_catalog.csv

Usage:
    python3 engines/rule/catalogs/export_ciem_catalog_csv.py
"""

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent.parent
OUT_DIR  = Path(__file__).resolve().parent
OUT_FILE = OUT_DIR / "ciem_log_rule_field_catalog.csv"

CIEM_DIRS = {
    "aws":   ROOT / "catalog" / "rule" / "aws_rule_ciem",
    "azure": ROOT / "catalog" / "rule" / "azure_rule_ciem",
    "gcp":   ROOT / "catalog" / "rule" / "gcp_rule_ciem",
    "oci":   ROOT / "catalog" / "rule" / "oci_rule_ciem",
    "ibm":   ROOT / "catalog" / "rule" / "ibm_rule_ciem",
    "k8s":   ROOT / "catalog" / "rule" / "k8s_rule_ciem",
}

# ─────────────────────────────────────────────────────────────────────────────
# Metadata tables (same as generator — field labels, service labels, format hints)
# ─────────────────────────────────────────────────────────────────────────────

SOURCE_TYPE_META = {
    "cloudtrail":     {"label": "AWS CloudTrail",                    "csp": "aws",   "default_for": "aws"},
    "azure_activity": {"label": "Azure Activity Log",                "csp": "azure", "default_for": "azure"},
    "gcp_audit":      {"label": "GCP Cloud Audit Logs",              "csp": "gcp",   "default_for": None},
    "oci_audit":      {"label": "OCI Audit Log",                     "csp": "oci",   "default_for": None},
    "ibm_activity":   {"label": "IBM Activity Tracker (CADF)",       "csp": "ibm",   "default_for": None},
    "eks_audit":      {"label": "AWS EKS Kubernetes Audit",          "csp": "aws",   "default_for": None},
    "k8s_audit":      {"label": "Kubernetes Audit Log",              "csp": "k8s",   "default_for": None},
    "ibm_k8s_audit":  {"label": "IBM IKS Kubernetes Audit",          "csp": "ibm",   "default_for": None},
    "ibm_db_audit":   {"label": "IBM Database Audit",                "csp": "ibm",   "default_for": None},
    "ibm_scc":        {"label": "IBM Security & Compliance Center",  "csp": "ibm",   "default_for": None},
    "oci_cloudguard": {"label": "OCI Cloud Guard",                   "csp": "oci",   "default_for": None},
    "oci_db_audit":   {"label": "OCI Database Audit",                "csp": "oci",   "default_for": None},
    "oci_k8s_audit":  {"label": "OCI OKE Kubernetes Audit",          "csp": "oci",   "default_for": None},
    "oci_vcn_flow":   {"label": "OCI VCN Flow Logs",                 "csp": "oci",   "default_for": None},
    "oci_waf":        {"label": "OCI WAF Logs",                      "csp": "oci",   "default_for": None},
    "rds_audit":      {"label": "AWS RDS Database Audit",            "csp": "aws",   "default_for": None},
    "s3_access":      {"label": "AWS S3 Access Logs",                "csp": "aws",   "default_for": None},
    "alb":            {"label": "AWS ALB Access Logs",               "csp": "aws",   "default_for": None},
    "cloudfront":     {"label": "AWS CloudFront Logs",               "csp": "aws",   "default_for": None},
    "vpc_flow":       {"label": "AWS VPC Flow Logs",                 "csp": "aws",   "default_for": None},
    "guardduty":      {"label": "AWS GuardDuty Findings",            "csp": "aws",   "default_for": None},
    "waf":            {"label": "AWS WAF Logs",                      "csp": "aws",   "default_for": None},
    "lambda":         {"label": "AWS Lambda Logs",                   "csp": "aws",   "default_for": None},
    "dns":            {"label": "AWS Route 53 DNS Logs",             "csp": "aws",   "default_for": None},
}

FIELD_META = {
    "source_type":         {"label": "Log Source Type",             "type": "fixed",  "ops": "equals"},
    "service":             {"label": "Service / Provider",          "type": "enum",   "ops": "equals, not_equals, in"},
    "operation":           {"label": "API Operation / Event Name",  "type": "string", "ops": "equals, not_equals, in, contains, starts_with, starts_with_any"},
    "outcome":             {"label": "Outcome",                     "type": "enum",   "ops": "equals, not_equals, in"},
    "error_code":          {"label": "Error Code",                  "type": "string", "ops": "equals, not_equals, in"},
    "actor.principal":     {"label": "Actor / User Identity",       "type": "string", "ops": "equals, not_equals, contains, starts_with"},
    "actor.principal_type":{"label": "Actor Type",                  "type": "enum",   "ops": "equals, not_equals, in"},
    "actor.ip_address":    {"label": "Actor IP Address",            "type": "string", "ops": "equals, contains, starts_with"},
    "actor.account_id":    {"label": "Actor Account ID",            "type": "string", "ops": "equals, in"},
    "resource.uid":        {"label": "Resource ID / ARN",           "type": "string", "ops": "equals, contains, starts_with"},
    "resource.type":       {"label": "Resource Type",               "type": "string", "ops": "equals, contains, in"},
    "resource.name":       {"label": "Resource Name",               "type": "string", "ops": "equals, contains, starts_with"},
    "resource.region":     {"label": "Resource Region",             "type": "enum",   "ops": "equals, in"},
    "severity":            {"label": "Event Severity",              "type": "enum",   "ops": "equals, not_equals, in"},
    "verb":                {"label": "K8s Verb",                    "type": "enum",   "ops": "equals, not_equals, in"},
    "resource":            {"label": "K8s Resource Kind",           "type": "string", "ops": "equals, in"},
    "subresource":         {"label": "K8s Subresource",             "type": "string", "ops": "equals"},
    "namespace":           {"label": "K8s Namespace",               "type": "string", "ops": "equals, contains"},
    "network.src_ip":      {"label": "Network Source IP",           "type": "string", "ops": "equals, starts_with"},
    "network.dst_ip":      {"label": "Network Dest IP",             "type": "string", "ops": "equals, starts_with"},
    "network.dst_port":    {"label": "Network Dest Port",           "type": "number", "ops": "equals, in"},
    "network.protocol":    {"label": "Network Protocol",            "type": "enum",   "ops": "equals"},
    "network.flow_action": {"label": "Flow Action",                 "type": "enum",   "ops": "equals"},
    "action":              {"label": "CADF Action (IBM full)",      "type": "string", "ops": "equals, contains, starts_with"},
    "event_type":          {"label": "Event Type",                  "type": "string", "ops": "equals, contains"},
    "risk_level":          {"label": "Risk Level",                  "type": "enum",   "ops": "equals, in"},
    "db_action":           {"label": "Database Action",             "type": "string", "ops": "equals, in"},
    "action_taken":        {"label": "WAF Action Taken",            "type": "enum",   "ops": "equals, in"},
    "threat_category":     {"label": "Threat Category",             "type": "string", "ops": "equals, in"},
}

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
        "cognito-idp": "Cognito User Pools",
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
        "wafv2": "WAF v2",
    },
    "azure_activity": {},
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
        "com.oraclecloud.networking": "Networking / VCN",
        "com.oraclecloud.vault": "Vault (Key Management)",
        "com.oraclecloud.containerengine": "OKE (Container Engine for K8s)",
        "com.oraclecloud.cloudguard": "Cloud Guard",
        "com.oraclecloud.logging": "Logging",
        "com.oraclecloud.resourcemanager": "Resource Manager",
        "com.oraclecloud.audit": "Audit Service",
    },
    "ibm_activity": {
        "iam_identity": "IAM Identity",
        "cloud_object_storage": "Cloud Object Storage (COS)",
        "is": "VPC / Virtual Server Instances",
        "containers_kubernetes": "IKS (Kubernetes Service)",
        "databases_for_postgresql": "Databases for PostgreSQL",
        "kms": "Key Protect",
        "security_compliance_center": "Security & Compliance Center",
        "secrets_manager": "Secrets Manager",
    },
}

FORMAT_HINTS = {
    "cloudtrail": {
        "service": "Lowercase, no .amazonaws.com — use 'iam' NOT 'IAM' or 'iam.amazonaws.com'",
        "operation": "PascalCase eventName — use 'CreateUser' NOT 'createuser' or 'create_user'",
    },
    "azure_activity": {
        "service": "Lowercase provider prefix — use 'compute' NOT 'Microsoft.Compute'",
        "operation": "Full ARM path — use 'Microsoft.Authorization/roleAssignments/write' NOT 'AssignRole'",
    },
    "gcp_audit": {
        "service": "Full googleapis.com name — use 'iam.googleapis.com' NOT 'iam' or 'IAM'",
        "operation": "Full gRPC method — use 'google.iam.v1.IAMPolicy.SetIamPolicy' NOT 'SetIamPolicy'",
    },
    "oci_audit": {
        "service": "Reversed-domain namespace — use 'com.oraclecloud.identitycontrolplane' NOT 'IAM'",
        "operation": "PascalCase last segment of eventType — use 'CreateUser' NOT 'createuser'",
    },
    "ibm_activity": {
        "service": "First CADF segment, hyphens→underscores — use 'iam_identity' NOT 'IAM' or 'iam-identity'",
        "operation": "Full CADF action string — use 'iam-identity.user-apikey.create' NOT 'create'",
    },
    "eks_audit": {
        "operation": "Lowercase K8s verb — use 'create' NOT 'Create' or 'CREATE'",
    },
    "k8s_audit": {
        "verb":      "Lowercase K8s verb — use 'create' NOT 'Create' or 'CREATE'",
        "resource":  "Lowercase plural — use 'pods' NOT 'Pod' or 'pod'",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Label generators
# ─────────────────────────────────────────────────────────────────────────────

def _pascal_to_words(name: str) -> str:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", s)
    return s.strip()

def _op_label(source_type: str, field: str, value: str) -> str:
    if field == "service":
        svc_map = SERVICE_LABELS.get(source_type, {})
        return svc_map.get(value, value.replace("-", " ").replace("_", " ").title())
    if field == "operation":
        if source_type in ("cloudtrail", "oci_audit"):
            return _pascal_to_words(value)
        if source_type == "gcp_audit":
            last = value.rsplit(".", 1)[-1]
            return _pascal_to_words(last)
        if source_type == "azure_activity":
            clean = value.replace("Microsoft.", "")
            parts = clean.split("/")
            verb_map = {"write": "Create/Update", "delete": "Delete", "read": "Read",
                        "action": "Execute", "listkeys": "List Keys"}
            verb = verb_map.get(parts[-1].lower(), parts[-1].title()) if parts else ""
            resource = " ".join(p.title().rstrip("s") for p in parts[1:-1]) if len(parts) > 2 else (parts[1].title() if len(parts) > 1 else "")
            return f"{parts[0]}: {verb} {resource}".strip()
        if source_type == "ibm_activity":
            parts = value.split(".")
            verb_map = {"create": "Create", "delete": "Delete", "update": "Update",
                        "read": "Read", "list": "List", "enable": "Enable", "disable": "Disable"}
            verb = verb_map.get(parts[-1].lower(), parts[-1].title()) if parts else ""
            res = " ".join(p.replace("-", " ").title() for p in parts[:-1])
            return f"{verb} {res}".strip()
        return value
    if field in ("verb",):
        return value.title()
    return value

# ─────────────────────────────────────────────────────────────────────────────
# Load and flatten all CIEM rules
# ─────────────────────────────────────────────────────────────────────────────

def _flatten_conds(conds: Any) -> List[Dict]:
    if isinstance(conds, dict):
        if "all" in conds:
            return list(conds["all"])
        if "field" in conds:
            return [conds]
    return []

def _cond_summary(all_conds: List[Dict]) -> str:
    parts = []
    for c in all_conds:
        f = c.get("field", "")
        op = c.get("op", "")
        v = c.get("value", "")
        if isinstance(v, list):
            v = "[" + ", ".join(str(x) for x in v[:3]) + (", ..." if len(v) > 3 else "") + "]"
        parts.append(f"{f} {op} {v}")
    return " AND ".join(parts)

def load_all_rules() -> List[Dict]:
    """Load every CIEM YAML and return a flat list of rule dicts."""
    rules = []
    default_st = {"aws": "cloudtrail", "azure": "azure_activity"}

    for csp, ciem_dir in CIEM_DIRS.items():
        if not ciem_dir.exists():
            continue
        for p in sorted(ciem_dir.rglob("*.yaml")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict) or "rule_id" not in data:
                continue

            cfg = data.get("check_config", {}) or {}
            top_conds = _flatten_conds(cfg.get("conditions", {}))

            # For log_correlation rules, also collect per-event conditions
            sub_event_conds: List[List[Dict]] = []
            for ev in cfg.get("events", []):
                ec = _flatten_conds(ev.get("conditions", {}))
                if ec:
                    sub_event_conds.append(ec)

            # Determine source_type
            all_conds_flat = top_conds[:]
            for sub in sub_event_conds:
                all_conds_flat.extend(sub)

            st = next(
                (c.get("value") for c in all_conds_flat
                 if c.get("field") == "source_type" and isinstance(c.get("value"), str)),
                default_st.get(csp),
            )

            rules.append({
                "csp":       csp,
                "rule_id":   data["rule_id"],
                "title":     data.get("title", data["rule_id"]),
                "severity":  data.get("severity", ""),
                "threat_category": data.get("threat_category", ""),
                "check_type": data.get("check_type", "log"),
                "source_type": st or "",
                "top_conds":  top_conds,
                "sub_event_conds": sub_event_conds,
                "all_conds":  all_conds_flat,
                "file":       str(p.relative_to(ROOT)),
            })
    return rules

# ─────────────────────────────────────────────────────────────────────────────
# Build CSV rows
# ─────────────────────────────────────────────────────────────────────────────

COLUMNS = [
    "csp",
    "source_type",
    "source_type_label",
    "log_field",
    "field_label",
    "field_type",
    "operators",
    "format_hint",
    "field_value",
    "field_value_label",
    "rule_id",
    "rule_title",
    "rule_severity",
    "rule_threat_category",
    "rule_check_type",
    "rule_condition_op",
    "rule_conditions_summary",
    "rule_conditions_json",
    "rule_file",
]

def build_rows(rules: List[Dict]) -> List[Dict]:
    rows = []

    for rule in rules:
        st    = rule["source_type"]
        csp   = rule["csp"]
        st_meta = SOURCE_TYPE_META.get(st, {"label": st, "csp": csp})

        # Use all conditions (top-level + all sub-event conditions merged)
        # For each condition block (top or sub-event), emit rows
        cond_blocks: List[Tuple[List[Dict], str]] = []
        if rule["top_conds"]:
            cond_blocks.append((rule["top_conds"], ""))
        for i, sub in enumerate(rule["sub_event_conds"], 1):
            cond_blocks.append((sub, f"event_{i}"))

        if not cond_blocks:
            # Rule has no conditions — still emit one row as reference
            rows.append({
                "csp": csp,
                "source_type": st,
                "source_type_label": st_meta["label"],
                "log_field": "",
                "field_label": "",
                "field_type": "",
                "operators": "",
                "format_hint": "",
                "field_value": "",
                "field_value_label": "",
                "rule_id": rule["rule_id"],
                "rule_title": rule["title"],
                "rule_severity": rule["severity"],
                "rule_threat_category": rule["threat_category"],
                "rule_check_type": rule["check_type"],
                "rule_condition_op": "",
                "rule_conditions_summary": "",
                "rule_conditions_json": "{}",
                "rule_file": rule["file"],
            })
            continue

        for conds, block_tag in cond_blocks:
            cond_summary = _cond_summary(conds)
            cond_json    = json.dumps({"all": conds})

            for cond in conds:
                field = cond.get("field", "")
                if not field or not isinstance(field, str):
                    continue
                op    = cond.get("op", "")
                value = cond.get("value", "")

                # Handle list values (in operator)
                value_entries: List[Tuple[str, str]] = []
                if isinstance(value, list):
                    for v in value:
                        if isinstance(v, str):
                            value_entries.append((v, _op_label(st, field, v)))
                elif isinstance(value, str):
                    value_entries.append((value, _op_label(st, field, value)))
                elif value is not None:
                    value_entries.append((str(value), str(value)))
                else:
                    value_entries.append(("", ""))

                fm  = FIELD_META.get(field, {"label": field.replace(".", " ").title(),
                                              "type": "string", "ops": "equals"})
                fhint = FORMAT_HINTS.get(st, {}).get(field, "")

                for fv, fv_label in value_entries:
                    rows.append({
                        "csp":               csp,
                        "source_type":       st,
                        "source_type_label": st_meta["label"],
                        "log_field":         field,
                        "field_label":       fm["label"],
                        "field_type":        fm["type"],
                        "operators":         fm["ops"],
                        "format_hint":       fhint,
                        "field_value":       fv,
                        "field_value_label": fv_label,
                        "rule_id":           rule["rule_id"],
                        "rule_title":        rule["title"],
                        "rule_severity":     rule["severity"],
                        "rule_threat_category": rule["threat_category"],
                        "rule_check_type":   rule["check_type"],
                        "rule_condition_op": op,
                        "rule_conditions_summary": cond_summary,
                        "rule_conditions_json": cond_json,
                        "rule_file":         rule["file"],
                    })

    # Sort: csp → source_type → log_field → field_value → rule_id
    rows.sort(key=lambda r: (
        r["csp"], r["source_type"], r["log_field"], r["field_value"], r["rule_id"]
    ))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Loading CIEM rules from {ROOT}/catalog/rule/...")
    rules = load_all_rules()
    print(f"  Loaded {len(rules)} rules")

    print("Building unified catalog rows...")
    rows = build_rows(rules)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows → {OUT_FILE}")

    # Summary
    by_csp: Dict[str, int] = {}
    by_st:  Dict[str, int] = {}
    by_field: Dict[str, int] = {}
    for r in rows:
        by_csp[r["csp"]] = by_csp.get(r["csp"], 0) + 1
        by_st[r["source_type"]] = by_st.get(r["source_type"], 0) + 1
        if r["log_field"]:
            by_field[r["log_field"]] = by_field.get(r["log_field"], 0) + 1

    print("\nRows by CSP:")
    for k, v in sorted(by_csp.items()):
        print(f"  {k:<10} {v:>5}")
    print("\nRows by source_type:")
    for k, v in sorted(by_st.items()):
        print(f"  {k:<25} {v:>5}")
    print("\nTop fields used:")
    for k, v in sorted(by_field.items(), key=lambda x: -x[1])[:15]:
        print(f"  {k:<35} {v:>5}")

    print("\nDone.")

if __name__ == "__main__":
    main()
