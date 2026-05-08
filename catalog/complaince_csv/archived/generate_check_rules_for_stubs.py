#!/usr/bin/env python3
"""
generate_check_rules_for_stubs.py
===================================
Creates check rule YAML entries for the 624 compliance_stub rules created by
create_missing_catalog_stubs.py.

Output:
  - catalog/rule/{csp}_rule_check/{service}/{rule_id}_stub.yaml
    For config stubs: YAML check with for_each + conditions
    For activity_log/audit stubs: YAML check with check_type: log
    For chain/ciem stubs: YAML check with check_type: log_correlation

Usage:
    python generate_check_rules_for_stubs.py --dry-run
    python generate_check_rules_for_stubs.py --write
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

ROOT    = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "rule"

CSPS = ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]

# Source type → CIEM log source
CSP_LOG_SOURCE = {
    "aws": "cloudtrail",
    "azure": "azure_monitor",
    "gcp": "cloud_audit",
    "oci": "oci_audit",
    "ibm": "ibm_activity_tracker",
    "alicloud": "actiontrail",
    "k8s": "k8s_audit",
}

OPERATION_HINTS = {
    "assume_role": "AssumeRole",
    "send_command": "SendCommand",
    "delete_trail": "DeleteTrail",
    "stop_logging": "StopLogging",
    "update_trail": "UpdateTrail",
    "create_user": "CreateUser",
    "delete_role": "DeleteRole",
    "attach_policy": "AttachRolePolicy",
    "disable_mfa": "DeactivateMFADevice",
    "create_access_key": "CreateAccessKey",
    "run_command": "RunCommand",
    "modify_security_group": "AuthorizeSecurityGroupIngress",
    "delete_bucket": "DeleteBucket",
    "audit_policy_change": "PutBucketPolicy",
    "log_tampering": "DeleteTrail",
    "privilege_escalation": "AssumeRole",
}


def load_stub_rules() -> Dict[str, List[str]]:
    """Return {csp: [rule_id, ...]} for all compliance_stub rules."""
    result: Dict[str, List[str]] = defaultdict(list)
    for csp in CSPS:
        d = CATALOG / f"{csp}_rule_metadata"
        if not d.exists():
            continue
        for f in d.rglob("*.yaml"):
            try:
                data = yaml.safe_load(f.read_text())
                if isinstance(data, dict) and data.get("source") == "compliance_stub":
                    result[csp].append(f.stem)
            except Exception:
                pass
    return result


def load_discovery_ids(csp: str) -> Dict[str, List[str]]:
    """Return {service: [discovery_id, ...]} for a CSP."""
    disc_map: Dict[str, List[str]] = defaultdict(list)
    check_dir = CATALOG / f"{csp}_rule_check"
    if not check_dir.exists():
        return disc_map
    for disc_file in check_dir.rglob("*discovery*.yaml"):
        try:
            data = yaml.safe_load(disc_file.read_text())
            if not isinstance(data, dict):
                continue
            svc = data.get("service", "")
            for disc in data.get("discovery", []):
                did = disc.get("discovery_id", "")
                if did and svc:
                    disc_map[svc].append(did)
        except Exception:
            pass
    return disc_map


def categorize(rule_id: str) -> str:
    """Return 'config', 'activity_log', 'audit', 'chain_ciem', or 'other'."""
    if "chain" in rule_id or "correlation" in rule_id:
        return "chain_ciem"
    if "activity_log" in rule_id:
        return "activity_log"
    if ".audit." in rule_id:
        return "audit"
    if "inventory" in rule_id:
        return "other"
    return "config"


def infer_severity(rule_id: str) -> str:
    tokens = set(rule_id.lower().split("."))
    if any(t in tokens for t in ("chain", "privilege", "escalation", "root", "critical", "tampering")):
        return "HIGH"
    return "MEDIUM"


def make_config_check(rule_id: str, discovery_id: str, severity: str) -> dict:
    """Generate a config-type check entry."""
    parts = rule_id.split(".")
    check_field = parts[-1] if parts else "value"
    # Guess a reasonable field from the discovery — we'll use 'item' as a placeholder
    return {
        "rule_id": rule_id,
        "for_each": discovery_id,
        "severity": severity,
        "conditions": {
            "var": f"item.{check_field}",
            "op": "exists",
            "value": None,
        },
    }


def make_log_check(rule_id: str, csp: str, severity: str) -> dict:
    """Generate a log/audit event-type check entry (check_type: log)."""
    log_source = CSP_LOG_SOURCE.get(csp, csp)
    parts = rule_id.split(".")
    # Try to extract operation hint from rule_id
    operation = None
    for key, op in OPERATION_HINTS.items():
        if key in rule_id:
            operation = op
            break

    conditions_list = [
        {"op": "equals", "field": "source_type", "value": log_source},
    ]
    if operation:
        conditions_list.append({"op": "equals", "field": "operation", "value": operation})
    else:
        # Use the last part of rule_id as operation hint
        op_hint = parts[-1].replace("_", " ").title().replace(" ", "")
        conditions_list.append({"op": "contains", "field": "operation", "value": op_hint})

    return {
        "rule_id": rule_id,
        "check_type": "log",
        "severity": severity,
        "conditions": {"all": conditions_list},
    }


def make_chain_check(rule_id: str, csp: str, severity: str) -> dict:
    """Generate a log_correlation chain-type check entry."""
    log_source = CSP_LOG_SOURCE.get(csp, csp)
    parts = rule_id.split(".")
    chain_name = parts[-1].replace("_", " ")
    return {
        "rule_id": rule_id,
        "check_type": "log_correlation",
        "severity": severity,
        "description": f"Detect {chain_name} via {log_source} event correlation",
        "conditions": {
            "all": [
                {"op": "equals", "field": "source_type", "value": log_source},
                {"op": "equals", "field": "outcome", "value": "SUCCESS"},
            ]
        },
        "sequence": [
            {
                "event": "initial",
                "conditions": [
                    {"op": "equals", "field": "source_type", "value": log_source},
                ],
            },
            {
                "event": "followup",
                "conditions": [
                    {"op": "equals", "field": "actor.principal", "value": "{{initial.actor.principal}}"},
                ],
            },
        ],
    }


def yaml_dump_check(check: dict) -> str:
    return yaml.dump(check, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Write files (default: dry-run)")
    args = parser.parse_args()

    stubs = load_stub_rules()
    total_stubs = sum(len(v) for v in stubs.values())
    print(f"Found {total_stubs} compliance_stub rules across {len(stubs)} CSPs")

    created = 0
    skipped_existing = 0
    no_discovery = []

    for csp, rule_ids in sorted(stubs.items()):
        disc_map = load_discovery_ids(csp)
        check_dir = CATALOG / f"{csp}_rule_check"
        check_dir.mkdir(exist_ok=True)

        print(f"\n[{csp}] {len(rule_ids)} stubs | {sum(len(v) for v in disc_map.values())} discovery_ids")

        for rule_id in sorted(rule_ids):
            cat = categorize(rule_id)
            parts = rule_id.split(".")
            service = parts[1] if len(parts) > 1 else "general"
            severity = infer_severity(rule_id)

            # Output path
            service_dir = check_dir / service
            out_path = service_dir / f"{rule_id}.check.yaml"

            if out_path.exists():
                skipped_existing += 1
                continue

            # Build check entry based on category
            if cat == "config":
                discovery_ids = disc_map.get(service, [])
                if not discovery_ids:
                    no_discovery.append(rule_id)
                    # Still create with placeholder discovery_id
                    disc_id = f"{csp}.{service}.list"
                else:
                    # Pick most relevant discovery_id (prefer the one that matches resource)
                    resource = parts[2] if len(parts) > 2 else ""
                    disc_id = next(
                        (d for d in discovery_ids if resource in d.lower()),
                        discovery_ids[0],
                    )
                check = make_config_check(rule_id, disc_id, severity)

            elif cat in ("activity_log", "audit"):
                check = make_log_check(rule_id, csp, severity)

            elif cat == "chain_ciem":
                check = make_chain_check(rule_id, csp, severity)

            else:  # other/inventory
                check = make_config_check(rule_id, f"{csp}.{service}.list", severity)

            # Wrap in YAML file structure
            yaml_content = f"""# Auto-generated check rule stub for {rule_id}
# Source: generate_check_rules_for_stubs.py
# Category: {cat}
# TODO: Review and update conditions to match actual resource fields
version: '1.0'
provider: {csp}
service: {service}
checks:
{yaml.dump([check], default_flow_style=False, allow_unicode=True, sort_keys=False).rstrip()}
"""

            if args.write:
                service_dir.mkdir(exist_ok=True)
                out_path.write_text(yaml_content, encoding="utf-8")
                created += 1
            else:
                created += 1  # count for dry-run

    print(f"\n{'Created' if args.write else 'Would create'} {created} check rule YAML files")
    print(f"Already existed: {skipped_existing}")
    print(f"Config rules without discovery ({len(no_discovery)}): using placeholder discovery_id")

    if no_discovery[:10]:
        print("No-discovery examples:")
        for r in no_discovery[:10]:
            print(f"  {r}")

    if not args.write:
        print("\n[DRY-RUN] Pass --write to create files.")


if __name__ == "__main__":
    main()
