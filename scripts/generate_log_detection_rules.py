#!/usr/bin/env python3
"""
Generate log-based detection rules from boto3 operation catalog.

Reads boto3_dependencies_with_python_names_fully_enriched.json for each service,
extracts write operations, classifies by security relevance, and generates
detection rules that map to CloudTrail event names.

Pipeline:
  1. Read boto3 deps → extract ALL operations
  2. Classify: read (config check) vs write (log detection)
  3. Group writes by action type (Create/Delete/Put/Modify/Attach/Detach)
  4. Map to security concepts (using CSPM_PRIORITY_FIELDS)
  5. Generate: per-service CloudTrail detection list + YAML rules
  6. Map to existing config rules where possible

Usage:
    python scripts/generate_log_detection_rules.py [--service ec2] [--output-dir rules/generated]
"""

import argparse
import json
import os
import re
import yaml
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Tuple

BOTO3_DIR = Path(__file__).parent.parent / "data_pythonsdk_backup" / "aws"

# Security-relevant resource nouns (operations touching these = security-relevant)
SECURITY_NOUNS = {
    # IAM / Access
    "Policy", "Role", "User", "Group", "AccessKey", "LoginProfile", "MFADevice",
    "InstanceProfile", "PermissionsBoundary", "SAMLProvider", "OpenIDConnectProvider",
    "ServiceLinkedRole", "AccountPasswordPolicy", "AccountAlias",
    # Encryption
    "Encryption", "ServerSideEncryption", "KmsKey", "Key", "KeyPolicy",
    "Certificate", "Secret",
    # Network / Access Control
    "SecurityGroup", "SecurityGroupIngress", "SecurityGroupEgress",
    "NetworkAcl", "NetworkAclEntry", "RouteTable", "Route",
    "VpcPeeringConnection", "FlowLog", "VpcEndpoint",
    "PublicAccessBlock", "PublicAccess",
    # Logging / Monitoring
    "Trail", "Logging", "Detector", "FlowLogs", "AccessLog",
    "MetricFilter", "Alarm", "EventSubscription",
    # Data Protection
    "BucketPolicy", "BucketAcl", "ObjectAcl", "BucketEncryption",
    "BucketReplication", "BucketVersioning", "BucketLifecycle",
    "ObjectLock", "ObjectRetention", "BackupPlan", "BackupVault",
    # Resource lifecycle (destructive)
    "Bucket", "Instance", "Cluster", "DBInstance", "DBCluster",
    "Table", "Function", "Volume", "Snapshot", "Image",
    "Stack", "Distribution", "HostedZone",
}

# Action types and their security classification
ACTION_CLASSIFICATION = {
    "Delete": {"category": "destructive", "default_severity": "high"},
    "Remove": {"category": "destructive", "default_severity": "high"},
    "Terminate": {"category": "destructive", "default_severity": "high"},
    "Deregister": {"category": "destructive", "default_severity": "medium"},
    "Disable": {"category": "weaken", "default_severity": "high"},
    "Revoke": {"category": "weaken", "default_severity": "high"},
    "Detach": {"category": "weaken", "default_severity": "medium"},
    "Stop": {"category": "weaken", "default_severity": "medium"},
    "Put": {"category": "modify", "default_severity": "medium"},
    "Modify": {"category": "modify", "default_severity": "medium"},
    "Update": {"category": "modify", "default_severity": "medium"},
    "Set": {"category": "modify", "default_severity": "low"},
    "Create": {"category": "create", "default_severity": "medium"},
    "Attach": {"category": "escalate", "default_severity": "high"},
    "Grant": {"category": "escalate", "default_severity": "high"},
    "Enable": {"category": "configure", "default_severity": "low"},
    "Authorize": {"category": "escalate", "default_severity": "high"},
    "Add": {"category": "escalate", "default_severity": "medium"},
    "Associate": {"category": "configure", "default_severity": "low"},
    "Register": {"category": "create", "default_severity": "medium"},
    "Import": {"category": "create", "default_severity": "low"},
    "Tag": {"category": "tag", "default_severity": "info"},
    "Untag": {"category": "tag", "default_severity": "info"},
}

# MITRE ATT&CK mapping by action category
MITRE_MAPPING = {
    "destructive": {"tactic": "impact", "technique": "T1485"},
    "weaken": {"tactic": "defense_evasion", "technique": "T1562"},
    "modify": {"tactic": "persistence", "technique": "T1098"},
    "create": {"tactic": "persistence", "technique": "T1136"},
    "escalate": {"tactic": "privilege_escalation", "technique": "T1484"},
    "configure": {"tactic": "persistence", "technique": "T1098"},
    "tag": None,
}


def load_service_operations(service: str) -> Dict:
    """Load all operations from boto3 deps file."""
    path = BOTO3_DIR / service / "boto3_dependencies_with_python_names_fully_enriched.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    # Handle both formats: {service: {independent:[], dependent:[]}} or direct
    if service in data:
        return data[service]
    return data


def extract_write_operations(svc_data: Dict) -> List[Dict]:
    """Extract write operations from service data."""
    all_ops = svc_data.get("independent", []) + svc_data.get("dependent", [])
    writes = []
    for op in all_ops:
        name = op.get("operation", "")
        # Skip read operations
        if any(name.startswith(p) for p in ["Describe", "List", "Get", "Head", "Check", "Lookup", "Search", "Query", "Scan", "Select", "Batch"]):
            continue
        writes.append(op)
    return writes


def classify_operation(operation_name: str, service: str) -> Dict:
    """Classify a write operation by security relevance and action type."""
    # Determine action prefix
    action_type = "other"
    action_info = {"category": "other", "default_severity": "info"}
    for prefix, info in ACTION_CLASSIFICATION.items():
        if operation_name.startswith(prefix):
            action_type = prefix
            action_info = info
            break

    # Extract resource noun
    noun = operation_name
    for prefix in ACTION_CLASSIFICATION.keys():
        if operation_name.startswith(prefix):
            noun = operation_name[len(prefix):]
            break

    # Check security relevance
    is_security_relevant = any(sn.lower() in noun.lower() for sn in SECURITY_NOUNS)

    # Elevate severity for security-relevant destructive/weaken operations
    severity = action_info["default_severity"]
    if is_security_relevant and action_info["category"] in ("destructive", "weaken"):
        severity = "critical"
    elif is_security_relevant and action_info["category"] in ("escalate",):
        severity = "high"

    # MITRE mapping
    mitre = MITRE_MAPPING.get(action_info["category"])

    # CloudTrail event name = same as operation name (CamelCase)
    cloudtrail_event = operation_name

    return {
        "operation": operation_name,
        "cloudtrail_event": cloudtrail_event,
        "action_type": action_type,
        "action_category": action_info["category"],
        "resource_noun": noun,
        "severity": severity,
        "is_security_relevant": is_security_relevant,
        "mitre_tactic": mitre["tactic"] if mitre else None,
        "mitre_technique": mitre["technique"] if mitre else None,
    }


def generate_service_rules(service: str, classified_ops: List[Dict]) -> List[Dict]:
    """Generate YAML rule entries for security-relevant operations."""
    rules = []
    for op in classified_ops:
        if not op["is_security_relevant"]:
            continue
        if op["severity"] == "info":
            continue  # Skip tagging/low-value ops

        rule_id = f"log.{service}.{_to_snake(op['operation'])}"
        rule = {
            "rule_id": rule_id,
            "engine": _determine_engine(op),
            "rule_source": "log",
            "log_source_type": "cloudtrail",
            "service": service,
            "severity": op["severity"],
            "title": f"{service.upper()}: {_humanize(op['operation'])} detected",
            "action_category": op["action_category"],
            "condition": {
                "all": [
                    {"field": "service", "op": "equals", "value": service},
                    {"field": "operation", "op": "equals", "value": op["cloudtrail_event"]},
                ]
            },
        }
        if op["mitre_tactic"]:
            rule["mitre_tactic"] = op["mitre_tactic"]
            rule["mitre_technique"] = op["mitre_technique"]

        rules.append(rule)
    return rules


def _determine_engine(op: Dict) -> str:
    """Determine which engine should consume this rule."""
    noun = op["resource_noun"].lower()
    cat = op["action_category"]

    if any(k in noun for k in ["policy", "role", "user", "group", "access", "login", "mfa", "saml", "oidc"]):
        return "ciem"
    if any(k in noun for k in ["encryption", "bucket", "object", "snapshot", "replication", "kms", "key"]):
        return "datasec"
    if any(k in noun for k in ["securitygroup", "acl", "route", "flow", "vpc", "network"]):
        return "network-security"
    if any(k in noun for k in ["trail", "logging", "detector", "alarm", "metric"]):
        return "threat"
    if cat in ("destructive", "weaken"):
        return "threat"
    return "threat"


def _to_snake(name: str) -> str:
    return re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_")


def _humanize(name: str) -> str:
    return re.sub(r"([A-Z])", r" \1", name).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", help="Single service to process")
    parser.add_argument("--output-dir", default="engines/ciem/rules/generated")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.service:
        services = [args.service]
    else:
        services = sorted([d.name for d in BOTO3_DIR.iterdir()
                          if d.is_dir() and (d / "boto3_dependencies_with_python_names_fully_enriched.json").exists()])

    total_ops = 0
    total_security = 0
    total_rules = 0
    summary = {}

    for service in services:
        svc_data = load_service_operations(service)
        if not svc_data:
            continue

        writes = extract_write_operations(svc_data)
        classified = [classify_operation(op["operation"], service) for op in writes]

        security_ops = [c for c in classified if c["is_security_relevant"]]
        rules = generate_service_rules(service, classified)

        total_ops += len(writes)
        total_security += len(security_ops)
        total_rules += len(rules)

        if rules:
            summary[service] = {
                "total_write_ops": len(writes),
                "security_relevant": len(security_ops),
                "rules_generated": len(rules),
                "by_category": defaultdict(int),
                "by_engine": defaultdict(int),
            }
            for r in rules:
                summary[service]["by_category"][r["action_category"]] += 1
                summary[service]["by_engine"][r["engine"]] += 1

            if not args.summary_only:
                # Write per-service rule file
                svc_file = output_dir / f"l1_{service}_log_rules.yaml"
                with open(svc_file, "w") as f:
                    yaml.dump(rules, f, default_flow_style=False, sort_keys=False)

    # Print summary
    print(f"\n{'='*60}")
    print(f"Log Detection Rule Generation Summary")
    print(f"{'='*60}")
    print(f"Services processed: {len(services)}")
    print(f"Total write operations: {total_ops}")
    print(f"Security-relevant: {total_security}")
    print(f"Rules generated: {total_rules}")
    print(f"\nTop services by rules:")
    for svc, info in sorted(summary.items(), key=lambda x: -x[1]["rules_generated"])[:20]:
        print(f"  {svc:30s} writes={info['total_write_ops']:4d} security={info['security_relevant']:3d} rules={info['rules_generated']:3d}")

    # Engine breakdown
    engine_counts = defaultdict(int)
    for svc, info in summary.items():
        for engine, count in info["by_engine"].items():
            engine_counts[engine] += count
    print(f"\nRules by engine:")
    for engine, count in sorted(engine_counts.items(), key=lambda x: -x[1]):
        print(f"  {engine:25s} {count}")

    # Write summary
    summary_file = output_dir / "_generation_summary.json"
    with open(summary_file, "w") as f:
        json.dump({
            "total_services": len(services),
            "total_write_ops": total_ops,
            "total_security_relevant": total_security,
            "total_rules": total_rules,
            "by_engine": dict(engine_counts),
            "by_service": {k: {**v, "by_category": dict(v["by_category"]), "by_engine": dict(v["by_engine"])} for k, v in summary.items()},
        }, f, indent=2)
    print(f"\nSummary saved: {summary_file}")


if __name__ == "__main__":
    main()
