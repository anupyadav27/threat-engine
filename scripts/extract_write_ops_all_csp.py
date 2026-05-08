#!/usr/bin/env python3
"""
Extract write operations + generate log detection rules for ALL CSPs.

Handles different file naming and structures:
  AWS:      boto3_dependencies_with_python_names_fully_enriched.json
  Azure:    azure_dependencies_with_python_names_fully_enriched.json
  GCP:      gcp_dependencies_with_python_names_fully_enriched.json
  OCI:      oci_dependencies_with_python_names_fully_enriched.json
  IBM:      ibm_dependencies_with_python_names_fully_enriched.json
  AliCloud: alicloud_dependencies_with_python_names_fully_enriched.json
"""

import json
import os
import re
import yaml
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path("/Users/apple/Desktop/threat-engine/data_pythonsdk_backup")
RULES_DIR = Path("/Users/apple/Desktop/threat-engine/engines/ciem/rules/generated")

CSP_CONFIG = {
    "aws": {"file_prefix": "boto3", "audit_log": "cloudtrail"},
    "azure": {"file_prefix": "azure", "audit_log": "activity_log"},
    "gcp": {"file_prefix": "gcp", "audit_log": "audit_log"},
    "oci": {"file_prefix": "oci", "audit_log": "audit_log"},
    "ibm": {"file_prefix": "ibm", "audit_log": "activity_tracker"},
    "alicloud": {"file_prefix": "alicloud", "audit_log": "actiontrail"},
}

# Engine classification by service name patterns (CSP-agnostic)
ENGINE_PATTERNS = {
    "ciem_engine": [
        "iam", "sso", "identity", "access-analyzer", "accessanalyzer",
        "organizations", "ram", "cognito", "sts", "ad", "directory",
        "authorization", "msi", "rbac", "policy",
    ],
    "datasec_engine": [
        "s3", "storage", "blob", "bucket", "dynamodb", "rds", "sql",
        "redshift", "glue", "athena", "lakeformation", "databrew",
        "dataexchange", "dms", "kafka", "kinesis", "firehose",
        "elasticsearch", "opensearch", "neptune", "docdb", "elasticache",
        "memorydb", "timestream", "keyspaces", "qldb", "cosmosdb",
        "bigquery", "spanner", "bigtable", "firestore", "datastore",
        "object_storage", "nosql", "cloudant",
    ],
    "network_engine": [
        "ec2", "vpc", "network", "elb", "elbv2", "loadbalancing",
        "directconnect", "globalaccelerator", "route53", "dns",
        "apigateway", "cloudfront", "waf", "shield", "firewall",
        "lattice", "appmesh", "virtual_network", "nsg", "compute.network",
        "core.vcn", "core.subnet",
    ],
    "ai_engine": [
        "sagemaker", "bedrock", "comprehend", "rekognition", "textract",
        "polly", "transcribe", "translate", "lex", "personalize",
        "forecast", "frauddetector", "lookout", "healthlake", "kendra",
        "qbusiness", "aiplatform", "vertexai", "machinelearning",
        "cognitiveservices", "openai",
    ],
    "container_engine": [
        "ecs", "ecr", "eks", "apprunner", "proton", "lightsail",
        "aks", "gke", "oke", "container", "kubernetes",
    ],
    "database_engine": [
        "rds", "aurora", "neptune", "docdb", "dynamodb", "elasticache",
        "memorydb", "redshift", "timestream", "keyspaces", "qldb",
        "sql", "mysql", "postgresql", "cosmosdb", "spanner",
        "bigtable", "firestore", "db_system", "autonomous_database",
    ],
    "encryption_engine": [
        "kms", "acm", "cloudhsm", "secretsmanager", "ssm",
        "keyvault", "cloudkms", "vault", "key_management", "secrets",
        "certificate", "key_protect",
    ],
    "threat_engine": [
        "cloudtrail", "cloudwatch", "logs", "config", "guardduty",
        "securityhub", "inspector", "detective", "macie", "auditmanager",
        "monitor", "sentinel", "security", "logging", "audit",
    ],
}

SECURITY_NOUNS = {
    "Policy", "Role", "User", "Group", "AccessKey", "LoginProfile",
    "MFADevice", "InstanceProfile", "PermissionsBoundary", "Permission",
    "SAMLProvider", "OpenIDConnectProvider", "PasswordPolicy", "Identity",
    "Encryption", "ServerSideEncryption", "KmsKey", "Key", "KeyPolicy",
    "Certificate", "Secret", "Grant", "Credential",
    "SecurityGroup", "SecurityGroupIngress", "SecurityGroupEgress",
    "NetworkAcl", "NetworkAclEntry", "RouteTable", "Route", "Firewall",
    "VpcPeeringConnection", "FlowLog", "VpcEndpoint", "NSG",
    "PublicAccessBlock", "PublicAccess", "PublicIP",
    "Trail", "Logging", "Detector", "Alarm", "MetricFilter", "Alert",
    "BucketPolicy", "BucketAcl", "BucketEncryption", "AccessPolicy",
    "BucketReplication", "BucketVersioning", "ObjectLock", "Backup",
    "Bucket", "Instance", "Cluster", "DBInstance", "DBCluster",
    "Table", "Function", "Volume", "Snapshot", "Image", "Disk",
    "Stack", "Distribution", "HostedZone", "WebACL", "IPSet", "RuleGroup",
    "Vault", "Container", "Pod", "Deployment", "Service",
}

ACTION_CLASSIFICATION = {
    "Delete": {"category": "destructive", "severity": "high"},
    "Remove": {"category": "destructive", "severity": "high"},
    "Terminate": {"category": "destructive", "severity": "high"},
    "Deregister": {"category": "destructive", "severity": "medium"},
    "Purge": {"category": "destructive", "severity": "critical"},
    "Destroy": {"category": "destructive", "severity": "critical"},
    "Disable": {"category": "weaken", "severity": "high"},
    "Revoke": {"category": "weaken", "severity": "high"},
    "Detach": {"category": "weaken", "severity": "medium"},
    "Stop": {"category": "weaken", "severity": "medium"},
    "Suspend": {"category": "weaken", "severity": "medium"},
    "Put": {"category": "modify", "severity": "medium"},
    "Modify": {"category": "modify", "severity": "medium"},
    "Update": {"category": "modify", "severity": "medium"},
    "Set": {"category": "modify", "severity": "low"},
    "Replace": {"category": "modify", "severity": "medium"},
    "Patch": {"category": "modify", "severity": "medium"},
    "Create": {"category": "create", "severity": "medium"},
    "Attach": {"category": "escalate", "severity": "high"},
    "Grant": {"category": "escalate", "severity": "high"},
    "Authorize": {"category": "escalate", "severity": "high"},
    "Add": {"category": "escalate", "severity": "medium"},
    "Assign": {"category": "escalate", "severity": "medium"},
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

READ_PREFIXES = [
    "Describe", "List", "Get", "Head", "Check", "Lookup", "Search",
    "Query", "Scan", "Select", "Batch", "Count", "Export", "Fetch",
    "Find", "Preview", "Simulate", "Test", "Validate", "Verify",
    "Read", "Show", "View", "Retrieve", "Discover", "Inspect",
]


def determine_engines(csp, service, noun):
    engines = []
    svc_lower = service.lower().replace("-", "").replace("_", "")
    noun_lower = noun.lower()

    for engine, patterns in ENGINE_PATTERNS.items():
        for p in patterns:
            p_clean = p.lower().replace("-", "").replace("_", "")
            if p_clean in svc_lower or p_clean in noun_lower:
                if engine not in engines:
                    engines.append(engine)
                break

    if not engines:
        engines.append("threat_engine")
    return engines


CATALOG_DIR = Path("/Users/apple/Desktop/threat-engine/catalog")

def load_operations(csp, service):
    dep_file = f"{CSP_CONFIG[csp]['file_prefix']}_dependencies_with_python_names_fully_enriched.json"
    path = BASE_DIR / csp / service / dep_file
    if not path.exists():
        return None

    data = json.loads(path.read_text())

    # Handle different structures
    svc_data = data.get(service, data)
    if not isinstance(svc_data, dict):
        # Try first key
        if isinstance(data, dict) and len(data) == 1:
            svc_data = list(data.values())[0]
        else:
            return None

    # Extract operations - handle different structures
    all_ops = []

    # AWS/Azure/IBM style: independent + dependent lists
    if "independent" in svc_data:
        all_ops = svc_data.get("independent", []) + svc_data.get("dependent", [])
    # OCI/generic style: operations list or dict
    elif "operations" in svc_data:
        ops = svc_data["operations"]
        if isinstance(ops, list):
            all_ops = [op if isinstance(op, dict) else {"operation": str(op)} for op in ops]
        elif isinstance(ops, dict):
            all_ops = list(ops.values()) if all(isinstance(v, dict) for v in ops.values()) else [{"operation": k} for k in ops]
    # Also try operations_by_category (Azure)
    elif "operations_by_category" in svc_data:
        for cat, ops in svc_data["operations_by_category"].items():
            if isinstance(ops, list):
                all_ops.extend([op if isinstance(op, dict) else {"operation": str(op)} for op in ops])
    # GCP style: resources with independent/dependent lists
    elif "resources" in svc_data:
        for res_name, res_data in svc_data.get("resources", {}).items():
            if isinstance(res_data, dict):
                # GCP has independent + dependent per resource
                for op in res_data.get("independent", []) + res_data.get("dependent", []):
                    if isinstance(op, dict):
                        name = op.get("operation", "")
                        if name:
                            op_entry = dict(op)
                            op_entry["operation"] = f"{res_name}.{name}" if "." not in name else name
                            all_ops.append(op_entry)
                # Also check methods dict
                for method_name, method_data in res_data.get("methods", {}).items():
                    op = {"operation": f"{res_name}.{method_name}"}
                    if isinstance(method_data, dict):
                        op["python_method"] = method_data.get("python_method", method_name)
                        op["required_params"] = method_data.get("required_params", [])
                    all_ops.append(op)

    return all_ops


def process_csp(csp):
    csp_dir = BASE_DIR / csp
    if not csp_dir.exists():
        return {}

    dep_pattern = f"{CSP_CONFIG[csp]['file_prefix']}_dependencies_with_python_names_fully_enriched.json"
    audit_log = CSP_CONFIG[csp]["audit_log"]

    services = sorted([d.name for d in csp_dir.iterdir()
                       if d.is_dir() and (d / dep_pattern).exists()])

    csp_stats = {"services": 0, "write_ops": 0, "rules": 0, "engines": defaultdict(int)}

    for service in services:
        all_ops = load_operations(csp, service)
        if not all_ops:
            continue

        reads = []
        writes = []
        for op in all_ops:
            name = op.get("operation", "") if isinstance(op, dict) else str(op)
            if not name:
                continue
            # For GCP: resource.method format
            method_name = name.split(".")[-1] if "." in name else name

            # OCI has operation_type field
            op_type = op.get("operation_type", "") if isinstance(op, dict) else ""
            if op_type:
                is_read = op_type.lower() in ("get", "list", "read", "search", "query")
            else:
                is_read = any(method_name.startswith(p) or method_name.lower().startswith(p.lower()) for p in READ_PREFIXES)
            entry = {
                "operation": name,
                "python_method": op.get("python_method", op.get("yaml_action", "")) if isinstance(op, dict) else "",
                "required_params": op.get("required_params", []) if isinstance(op, dict) else [],
                "audit_log_event": name,
            }
            if is_read:
                reads.append(entry)
            else:
                writes.append(entry)

        # Fallback 0: if no writes, check pre-extracted write_operations.json
        # (may have been generated by OCI SDK extraction script)
        if not writes:
            wo_path = csp_dir / service / "write_operations.json"
            if wo_path.exists():
                try:
                    wo = json.loads(wo_path.read_text())
                    if wo.get("total_write", 0) > 0:
                        for op in wo.get("write_operations", []):
                            if isinstance(op, dict) and op.get("operation"):
                                writes.append(op)
                except Exception:
                    pass

        # Fallback 1: if no writes found, check catalog/step2_write_operation_registry
        if not writes:
            step2_write = CATALOG_DIR / csp / service / "step2_write_operation_registry.json"
            if step2_write.exists():
                try:
                    wd = json.loads(step2_write.read_text())
                    w_ops = wd.get("write_operations", wd.get("operations", []))
                    if isinstance(w_ops, list):
                        for op in w_ops:
                            name = op.get("operation", op) if isinstance(op, dict) else str(op)
                            if name:
                                writes.append({
                                    "operation": name,
                                    "python_method": op.get("python_method", "") if isinstance(op, dict) else "",
                                    "required_params": op.get("required_params", []) if isinstance(op, dict) else [],
                                    "audit_log_event": name,
                                })
                except Exception:
                    pass

        # Save write_operations.json (only if we have new data or no existing data)
        write_ops_path = csp_dir / service / "write_operations.json"
        # Don't overwrite if we have 0 writes but existing file has data
        if writes or not write_ops_path.exists():
            write_ops_path.write_text(json.dumps({
            "csp": csp,
            "service": service,
            "audit_log_type": audit_log,
            "total_read": len(reads),
            "total_write": len(writes),
            "read_operations": [r["operation"] for r in reads],
            "write_operations": writes,
        }, indent=2))

        # Generate rules
        rules = []
        for w in writes:
            name = w["operation"]
            method_name = name.split(".")[-1] if "." in name else name

            action_type = "other"
            action_info = {"category": "other", "severity": "info"}
            for prefix, info in ACTION_CLASSIFICATION.items():
                if method_name.startswith(prefix) or method_name.lower().startswith(prefix.lower()):
                    action_type = prefix
                    action_info = info
                    break

            noun = method_name
            for prefix in ACTION_CLASSIFICATION:
                if method_name.startswith(prefix):
                    noun = method_name[len(prefix):]
                    break
                if method_name.lower().startswith(prefix.lower()):
                    noun = method_name[len(prefix):]
                    break

            is_security = any(sn.lower() in noun.lower() for sn in SECURITY_NOUNS)
            engines = determine_engines(csp, service, noun)

            severity = action_info["severity"]
            if is_security and action_info["category"] in ("destructive", "weaken"):
                severity = "critical"
            elif is_security and action_info["category"] == "escalate":
                severity = "high"

            if not is_security and severity in ("info", "low"):
                continue

            mitre = MITRE_MAPPING.get(action_info["category"], {})

            rule = {
                "rule_id": f"log.{csp}.{service}.{_to_snake(method_name)}",
                "csp": csp,
                "rule_source": "log",
                "log_source_type": audit_log,
                "service": service,
                "resource_noun": noun,
                "engines": engines,
                "primary_engine": engines[0],
                "severity": severity,
                "action_category": action_info["category"],
                "title": f"{csp.upper()} {service.upper()}: {_humanize(method_name)}",
                "audit_log_event": name,
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

        if rules:
            rules_path = RULES_DIR / csp / f"l1_{service}_log_rules.yaml"
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            with open(rules_path, "w") as f:
                yaml.dump(rules, f, default_flow_style=False, sort_keys=False)

        csp_stats["services"] += 1
        csp_stats["write_ops"] += len(writes)
        csp_stats["rules"] += len(rules)
        for r in rules:
            for e in r["engines"]:
                csp_stats["engines"][e] += 1

    return csp_stats


def _to_snake(name):
    return re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_").replace(".", "_")

def _humanize(name):
    return re.sub(r"([A-Z])", r" \1", name).strip()


def main():
    grand_total = {"services": 0, "write_ops": 0, "rules": 0, "engines": defaultdict(int)}

    for csp in CSP_CONFIG:
        print(f"\nProcessing {csp.upper()}...")
        stats = process_csp(csp)
        if stats:
            print(f"  Services: {stats['services']}, Write ops: {stats['write_ops']}, Rules: {stats['rules']}")
            grand_total["services"] += stats["services"]
            grand_total["write_ops"] += stats["write_ops"]
            grand_total["rules"] += stats["rules"]
            for e, c in stats["engines"].items():
                grand_total["engines"][e] += c

    print(f"\n{'='*60}")
    print(f"ALL CSPs — Write Ops + Rule Generation Complete")
    print(f"{'='*60}")
    print(f"Total services: {grand_total['services']}")
    print(f"Total write ops: {grand_total['write_ops']}")
    print(f"Total rules: {grand_total['rules']}")
    print(f"\nBy engine:")
    for e, c in sorted(grand_total["engines"].items(), key=lambda x: -x[1]):
        print(f"  {e:25s} {c}")

    # Count rule files per CSP
    print(f"\nRule files by CSP:")
    for csp in CSP_CONFIG:
        csp_rules_dir = RULES_DIR / csp
        if csp_rules_dir.exists():
            count = len(list(csp_rules_dir.glob("*.yaml")))
            print(f"  {csp:10s} {count} files")


if __name__ == "__main__":
    main()
