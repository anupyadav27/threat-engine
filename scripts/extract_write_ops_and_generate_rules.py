#!/usr/bin/env python3
"""
Extract write operations per service AND generate log detection rules.

1. Reads boto3_dependencies per service from data_pythonsdk_backup
2. Saves write_operations.json in each service folder
3. Generates log detection rules with proper engine + source tagging

Engines:
  - api_engine (CSPM check engine — config rules)
  - ciem_engine (IAM/entitlement — log rules)
  - threat_engine (threat detection — log rules)
  - datasec_engine (data security — log rules)
  - network_engine (network security — log rules)
  - ai_engine (AI/ML security — log rules)
  - database_engine (database security — log rules)
  - encryption_engine (encryption/key management — log rules)
  - container_engine (container/k8s security — log rules)

Usage:
    python scripts/extract_write_ops_and_generate_rules.py
"""

import json
import os
import re
import yaml
from pathlib import Path
from collections import defaultdict

BOTO3_DIR = Path("/Users/apple/Desktop/threat-engine/data_pythonsdk_backup/aws")
RULES_DIR = Path("/Users/apple/Desktop/threat-engine/engines/ciem/rules/generated")

# ══════════════════════════════════════════════════════════════
# Engine classification: service → primary engine
# ══════════════════════════════════════════════════════════════

# IAM/Identity services → ciem_engine
CIEM_SERVICES = {
    "iam", "sso", "sso-admin", "sso-oidc", "identitystore", "cognito-idp",
    "cognito-identity", "cognito-sync", "sts", "organizations", "ram",
    "access-analyzer", "accessanalyzer",
}

# Data services → datasec_engine
DATASEC_SERVICES = {
    "s3", "s3control", "s3outposts", "dynamodb", "dynamodbstreams",
    "rds", "redshift", "redshift-data", "redshift-serverless",
    "glue", "athena", "lakeformation", "databrew", "dataexchange",
    "datapipeline", "dms", "kafka", "kinesis", "kinesisanalytics",
    "firehose", "elasticsearch", "opensearch", "opensearchserverless",
    "neptune", "docdb", "docdb-elastic", "elasticache", "memorydb",
    "timestream-write", "timestream-query", "keyspaces", "qldb",
}

# Network services → network_engine
NETWORK_SERVICES = {
    "ec2", "vpc", "vpcflowlogs", "eip", "elb", "elbv2",
    "elasticloadbalancing", "directconnect", "globalaccelerator",
    "networkmanager", "network-firewall", "route53", "route53domains",
    "route53resolver", "apigateway", "apigatewayv2", "appmesh",
    "cloudfront", "waf", "wafv2", "waf-regional", "shield",
    "vpc-lattice",
}

# AI/ML services → ai_engine
AI_SERVICES = {
    "sagemaker", "sagemaker-runtime", "bedrock", "bedrock-runtime",
    "bedrock-agent", "bedrock-agent-runtime", "comprehend",
    "rekognition", "textract", "polly", "transcribe", "translate",
    "lex-models", "lex-runtime", "lexv2-models", "lexv2-runtime",
    "personalize", "forecast", "frauddetector", "lookoutmetrics",
    "lookoutequipment", "lookoutvision", "healthlake", "kendra",
    "qbusiness", "q",
}

# Container/K8s services → container_engine
CONTAINER_SERVICES = {
    "ecs", "ecr", "ecr-public", "eks", "eks-auth",
    "apprunner", "proton", "lightsail",
}

# Database services → database_engine
DATABASE_SERVICES = {
    "rds", "aurora", "neptune", "docdb", "docdb-elastic",
    "dynamodb", "elasticache", "memorydb", "redshift",
    "timestream-write", "keyspaces", "qldb",
}

# Encryption/Key services → encryption_engine
ENCRYPTION_SERVICES = {
    "kms", "acm", "acm-pca", "cloudhsm", "cloudhsmv2",
    "secretsmanager", "ssm",
}

# Audit/Logging services → threat_engine
AUDIT_SERVICES = {
    "cloudtrail", "cloudwatch", "logs", "config", "guardduty",
    "securityhub", "inspector", "inspector2", "detective",
    "macie2", "auditmanager", "cloudtrail-data",
}

# Security-relevant resource nouns
SECURITY_NOUNS = {
    "Policy", "Role", "User", "Group", "AccessKey", "LoginProfile",
    "MFADevice", "InstanceProfile", "PermissionsBoundary",
    "SAMLProvider", "OpenIDConnectProvider", "PasswordPolicy",
    "Encryption", "ServerSideEncryption", "KmsKey", "Key", "KeyPolicy",
    "Certificate", "Secret", "Grant",
    "SecurityGroup", "SecurityGroupIngress", "SecurityGroupEgress",
    "NetworkAcl", "NetworkAclEntry", "RouteTable", "Route",
    "VpcPeeringConnection", "FlowLog", "VpcEndpoint",
    "PublicAccessBlock", "PublicAccess",
    "Trail", "Logging", "Detector", "Alarm", "MetricFilter",
    "BucketPolicy", "BucketAcl", "BucketEncryption",
    "BucketReplication", "BucketVersioning", "ObjectLock",
    "Bucket", "Instance", "Cluster", "DBInstance", "DBCluster",
    "Table", "Function", "Volume", "Snapshot", "Image",
    "Stack", "Distribution", "HostedZone",
    "Firewall", "WebACL", "IPSet", "RuleGroup",
}

ACTION_CLASSIFICATION = {
    "Delete": {"category": "destructive", "severity": "high"},
    "Remove": {"category": "destructive", "severity": "high"},
    "Terminate": {"category": "destructive", "severity": "high"},
    "Deregister": {"category": "destructive", "severity": "medium"},
    "Disable": {"category": "weaken", "severity": "high"},
    "Revoke": {"category": "weaken", "severity": "high"},
    "Detach": {"category": "weaken", "severity": "medium"},
    "Stop": {"category": "weaken", "severity": "medium"},
    "Put": {"category": "modify", "severity": "medium"},
    "Modify": {"category": "modify", "severity": "medium"},
    "Update": {"category": "modify", "severity": "medium"},
    "Set": {"category": "modify", "severity": "low"},
    "Create": {"category": "create", "severity": "medium"},
    "Attach": {"category": "escalate", "severity": "high"},
    "Grant": {"category": "escalate", "severity": "high"},
    "Authorize": {"category": "escalate", "severity": "high"},
    "Add": {"category": "escalate", "severity": "medium"},
    "Enable": {"category": "configure", "severity": "low"},
    "Associate": {"category": "configure", "severity": "low"},
    "Register": {"category": "create", "severity": "medium"},
}

MITRE_MAPPING = {
    "destructive": {"tactic": "impact", "technique": "T1485"},
    "weaken": {"tactic": "defense_evasion", "technique": "T1562"},
    "modify": {"tactic": "persistence", "technique": "T1098"},
    "create": {"tactic": "persistence", "technique": "T1136"},
    "escalate": {"tactic": "privilege_escalation", "technique": "T1484"},
    "configure": {"tactic": "defense_evasion", "technique": "T1562"},
}


def determine_engine(service: str, op_name: str, noun: str) -> list:
    """Determine which engines should receive this rule. Returns list of tags."""
    engines = []

    # Primary engine from service
    if service in CIEM_SERVICES:
        engines.append("ciem_engine")
    if service in DATASEC_SERVICES:
        engines.append("datasec_engine")
    if service in NETWORK_SERVICES:
        engines.append("network_engine")
    if service in AI_SERVICES:
        engines.append("ai_engine")
    if service in CONTAINER_SERVICES:
        engines.append("container_engine")
    if service in DATABASE_SERVICES:
        engines.append("database_engine")
    if service in ENCRYPTION_SERVICES:
        engines.append("encryption_engine")
    if service in AUDIT_SERVICES:
        engines.append("threat_engine")

    # Cross-engine: IAM-related operations in any service → ciem
    noun_lower = noun.lower()
    if any(k in noun_lower for k in ["policy", "role", "user", "group", "access", "permission", "login", "mfa"]):
        if "ciem_engine" not in engines:
            engines.append("ciem_engine")

    # Cross-engine: encryption in any service → encryption
    if any(k in noun_lower for k in ["encrypt", "kms", "key", "certificate", "secret"]):
        if "encryption_engine" not in engines:
            engines.append("encryption_engine")

    # Cross-engine: destructive on data stores → datasec
    if any(k in noun_lower for k in ["bucket", "object", "snapshot", "backup", "replication"]):
        if "datasec_engine" not in engines:
            engines.append("datasec_engine")

    # Cross-engine: logging/monitoring changes → threat
    if any(k in noun_lower for k in ["trail", "logging", "detector", "alarm", "monitor"]):
        if "threat_engine" not in engines:
            engines.append("threat_engine")

    # Default: threat if nothing matched
    if not engines:
        engines.append("threat_engine")

    return engines


def process_service(service: str) -> dict:
    """Process one service: extract writes, save to folder, generate rules."""
    boto3_path = BOTO3_DIR / service / "boto3_dependencies_with_python_names_fully_enriched.json"
    if not boto3_path.exists():
        return {}

    data = json.loads(boto3_path.read_text())
    svc_data = data.get(service, data)

    if not isinstance(svc_data, dict):
        return {}

    all_ops = svc_data.get("independent", []) + svc_data.get("dependent", [])

    # Separate read and write
    reads = []
    writes = []
    for op in all_ops:
        name = op.get("operation", "")
        if not name:
            continue
        is_read = any(name.startswith(p) for p in
                      ["Describe", "List", "Get", "Head", "Check", "Lookup",
                       "Search", "Query", "Scan", "Select", "Batch", "Count",
                       "Export", "Fetch", "Find", "Preview", "Simulate", "Test",
                       "Validate", "Verify"])
        if is_read:
            reads.append({"operation": name, "python_method": op.get("python_method", op.get("yaml_action", "")),
                          "required_params": op.get("required_params", [])})
        else:
            writes.append({"operation": name, "python_method": op.get("python_method", op.get("yaml_action", "")),
                           "required_params": op.get("required_params", []),
                           "cloudtrail_event": name})

    # Save write_operations.json in the service folder
    write_ops_path = BOTO3_DIR / service / "write_operations.json"
    write_ops_data = {
        "service": service,
        "total_read": len(reads),
        "total_write": len(writes),
        "read_operations": [r["operation"] for r in reads],
        "write_operations": writes,
    }
    write_ops_path.write_text(json.dumps(write_ops_data, indent=2))

    # Classify and generate rules
    rules = []
    for w in writes:
        name = w["operation"]

        # Get action type
        action_type = "other"
        action_info = {"category": "other", "severity": "info"}
        for prefix, info in ACTION_CLASSIFICATION.items():
            if name.startswith(prefix):
                action_type = prefix
                action_info = info
                break

        # Extract noun
        noun = name
        for prefix in ACTION_CLASSIFICATION:
            if name.startswith(prefix):
                noun = name[len(prefix):]
                break

        # Security relevance
        is_security = any(sn.lower() in noun.lower() for sn in SECURITY_NOUNS)

        # Determine engines
        engines = determine_engine(service, name, noun)

        # Severity escalation for security-critical
        severity = action_info["severity"]
        if is_security and action_info["category"] in ("destructive", "weaken"):
            severity = "critical"
        elif is_security and action_info["category"] == "escalate":
            severity = "high"

        # Skip info-level non-security ops
        if not is_security and severity in ("info", "low"):
            continue

        mitre = MITRE_MAPPING.get(action_info["category"], {})

        rule = {
            "rule_id": f"log.{service}.{_to_snake(name)}",
            "rule_source": "log",
            "log_source_type": "cloudtrail",
            "service": service,
            "resource_noun": noun,
            "engines": engines,
            "primary_engine": engines[0],
            "severity": severity,
            "action_category": action_info["category"],
            "title": f"{service.upper()}: {_humanize(name)}",
            "cloudtrail_event": name,
            "is_security_relevant": is_security,
            "condition": {
                "all": [
                    {"field": "service", "op": "equals", "value": service},
                    {"field": "operation", "op": "equals", "value": name},
                ]
            },
        }
        if mitre:
            rule["mitre_tactic"] = mitre.get("tactic", "")
            rule["mitre_technique"] = mitre.get("technique", "")

        rules.append(rule)

    # Save rules YAML
    if rules:
        rules_path = RULES_DIR / f"l1_{service}_log_rules.yaml"
        with open(rules_path, "w") as f:
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False)

    return {
        "service": service,
        "total_ops": len(all_ops),
        "read_ops": len(reads),
        "write_ops": len(writes),
        "rules": len(rules),
        "security_relevant": sum(1 for r in rules if r["is_security_relevant"]),
    }


def _to_snake(name):
    return re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_")


def _humanize(name):
    return re.sub(r"([A-Z])", r" \1", name).strip()


def main():
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    services = sorted([d.name for d in BOTO3_DIR.iterdir()
                       if d.is_dir() and (d / "boto3_dependencies_with_python_names_fully_enriched.json").exists()])

    total = {"services": 0, "write_ops_saved": 0, "rules": 0}
    engine_counts = defaultdict(int)

    for service in services:
        result = process_service(service)
        if result:
            total["services"] += 1
            total["write_ops_saved"] += result["write_ops"]
            total["rules"] += result["rules"]

    # Count by engine from generated rules
    for rule_file in RULES_DIR.glob("l1_*_log_rules.yaml"):
        rules = yaml.safe_load(rule_file.read_text()) or []
        for r in rules:
            for e in r.get("engines", []):
                engine_counts[e] += 1

    print(f"\n{'='*60}")
    print(f"Write Operations + Rule Generation Complete")
    print(f"{'='*60}")
    print(f"Services: {total['services']}")
    print(f"Write operations saved: {total['write_ops_saved']} (per-service write_operations.json)")
    print(f"Rules generated: {total['rules']}")
    print(f"\nRules by engine:")
    for e, c in sorted(engine_counts.items(), key=lambda x: -x[1]):
        print(f"  {e:25s} {c}")


if __name__ == "__main__":
    main()
