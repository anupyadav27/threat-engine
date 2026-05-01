#!/usr/bin/env python3
"""
Disable OCI check rules that are clearly from AWS/GCP/Azure and have no OCI equivalent.

Strategy:
  1. Detect cross-cloud rules by matching check_name against cloud-specific patterns
  2. Set is_active: false in the YAML (never delete — keeps audit trail)
  3. Rebuild unified catalog CSV

Cross-cloud rules detected:
  - AWS EC2/EBS/Networking: securitygroup, networkacl, ami_, ebs_, elastic_ip, ...
  - AWS OpenSearch: service_domains_cloudwatch, service_domains_internal_user_database, ...
  - AWS API Gateway: api_security_monitoring_access_log, ...
  - AWS Athena: workgroup, athena_
  - GCP: project_os_login, instance_block_project_wide_ssh_keys
  - Azure: ensure_using_managed_disks, trusted_launch_enabled
"""
from __future__ import annotations
import subprocess, sys
from pathlib import Path
from collections import defaultdict

import yaml

BASE         = Path("/Users/apple/Desktop/threat-engine")
RULE_DIR     = BASE / "catalog/rule/oci_rule_check"
MERGE_SCRIPT = BASE / "catalog/discovery_generator/oci/merge_field_rule_catalog.py"

DRY_RUN = "--dry-run" in sys.argv

# ── Cross-cloud patterns ────────────────────────────────────────────────────────
# Each entry matches against the check_name (last segment of rule_id, lowercased).
# Pattern is a substring match.

CROSS_CLOUD_PATTERNS = [
    # AWS EC2 / compute-specific
    "securitygroup",          # AWS Security Groups (OCI uses NSG/Security Lists)
    "networkacl",             # AWS Network ACLs (OCI uses VCN Security Rules)
    "ami_",                   # AWS AMI (OCI has Custom Images)
    "ebs_",                   # AWS EBS (OCI has Block Volumes)
    "elastic_ip",             # AWS Elastic IP (OCI has Reserved Public IPs)
    "launch_template",        # AWS Launch Templates
    "_ssm_",                  # AWS Systems Manager
    "client_vpn",             # AWS Client VPN
    "transitgateway_auto_accept_vpc",   # AWS Transit Gateway VPC attachment
    "fleet_default_internet_access_disabled",  # AWS EC2 Fleet
    "dedicated_host_instance_auto_placement",  # AWS Dedicated Hosts
    "documents_set_as_public",   # AWS SSM Documents
    "document_secrets",          # AWS SSM Documents
    "instance_managed_by_ssm",   # AWS SSM
    "maintenance_execution_roles",  # AWS Patch Manager
    "patch_approval_rules_defined",   # AWS Patch Manager
    "patch_baseline_defined_for_os",  # AWS Patch Manager
    # AWS networking
    "subnet_flow_logs_enabled",      # AWS VPC Flow Logs (OCI has VCN Flow Logs)
    "cloudfront",                    # AWS CloudFront
    # AWS Athena
    "workgroup",                     # AWS Athena Workgroups
    # AWS API Gateway
    "api_security_monitoring_access_log",       # AWS API GW access logs
    "api_security_monitoring_execution_logging", # AWS API GW execution
    # AWS OpenSearch / Elasticsearch
    "service_domains_cloudwatch",              # AWS OpenSearch+CloudWatch
    "service_domains_internal_user_database",  # AWS OpenSearch internal auth
    "service_domains_fault_tolerant",          # AWS OpenSearch fault tolerance
    "service_domains_node_to_node",            # AWS OpenSearch node-to-node
    # AWS CloudWatch / CloudTrail
    "cloudwatch",
    "cloudtrail",
    # AWS traffic analysis
    "traffic_analysis_ids_ips",
    "traffic_analysis_alert_destinations",
    # AWS IAM / SCP
    "scp_mandatory",
    "aws_attached_policy",
    # GCP specific
    "project_os_login_enabled",
    "instance_block_project_wide_ssh_keys_disabled",
    # Azure specific
    "ensure_using_managed_disks",
    "trusted_launch_enabled",
]


def is_cross_cloud(check_name: str) -> str | None:
    """Return matching pattern if cross-cloud, else None."""
    name = check_name.lower()
    for pat in CROSS_CLOUD_PATTERNS:
        if pat in name:
            return pat
    return None


def process_yaml(yaml_path: Path, dry_run: bool) -> tuple[int, int]:
    """Mark cross-cloud rules as is_active: false. Returns (disabled, total)."""
    data = yaml.safe_load(yaml_path.read_text())
    if not isinstance(data, dict) or "checks" not in data:
        return 0, 0

    disabled = 0
    total    = len(data["checks"])
    for chk in data["checks"]:
        rid        = chk.get("rule_id", "")
        check_name = rid.split(".")[-1]
        pat        = is_cross_cloud(check_name)
        if pat:
            # Only disable if not already disabled
            if chk.get("is_active", True) is not False:
                chk["is_active"] = False
                disabled += 1
                if dry_run:
                    print(f"    DISABLE [{pat}]  {rid}")

    if disabled and not dry_run:
        yaml_path.write_text(
            yaml.dump(data, default_flow_style=False, allow_unicode=True,
                      sort_keys=False, width=120)
        )
    return disabled, total


def main():
    total_disabled   = 0
    total_rules      = 0
    affected_services = 0

    for svc_dir in sorted(RULE_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        yaml_files = list(svc_dir.glob("*.checks.yaml"))
        if not yaml_files:
            continue

        svc_disabled = 0
        svc_total    = 0
        for yf in yaml_files:
            d, t = process_yaml(yf, DRY_RUN)
            svc_disabled += d
            svc_total    += t

        if svc_disabled:
            affected_services += 1
            total_disabled    += svc_disabled
            total_rules       += svc_total
            flag = "(dry-run)" if DRY_RUN else ""
            print(f"  {svc_dir.name:<35} disabled {svc_disabled:>4}/{svc_total:<4} {flag}")

    print()
    print(f"TOTAL: {total_disabled} rules disabled across {affected_services} services")
    print(f"(dry_run={DRY_RUN})")

    if not DRY_RUN and total_disabled:
        print("\nRebuilding unified catalog ...")
        r = subprocess.run(
            [sys.executable, str(MERGE_SCRIPT)],
            capture_output=True, text=True
        )
        print(r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout)
        if r.returncode:
            print("WARN:", r.stderr[-500:])


if __name__ == "__main__":
    main()
