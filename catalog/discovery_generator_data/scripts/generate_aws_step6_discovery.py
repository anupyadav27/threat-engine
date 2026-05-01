#!/usr/bin/env python3
"""
Regenerate step6_{service}.discovery.yaml for ALL 446 AWS services.

Fixes over v1:
  - Action names: boto3 snake_case (describe_instances, not describeInstances)
  - Dependency wiring: for_each + params from step3 entity_paths
  - items_for: from step4 main_output_field (most accurate list container)
  - item fields: from step4 PascalCase field index or step2 output_fields fallback

INPUT per service directory:
  step2_read_operation_registry.json      → read ops, required_params, output_fields
  step3_read_operation_dependency_chain.json → dependency chains (roots + entity_paths)
  step4_fields_produced_index.json        → field→op index with main_output_field

OUTPUT per service directory:
  step6_{service}.discovery.yaml  (overwritten)

Usage:
    python3 data_pythonsdk/scripts/generate_aws_step6_discovery.py
    python3 data_pythonsdk/scripts/generate_aws_step6_discovery.py --dry-run
    python3 data_pythonsdk/scripts/generate_aws_step6_discovery.py --service elasticfilesystem
"""

import argparse
import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

AWS_ROOT = Path(__file__).parent.parent / "aws"
SKIP = {"tools", "__pycache__", "temp_code"}

# Fields to skip in item: sections (pagination, metadata, not CSPM-useful)
SKIP_FIELDS = {
    "NextToken", "Marker", "IsTruncated", "NextMarker",
    "ResponseMetadata", "ContinuationToken", "PageToken",
    "MaxResults", "RequestId", "nextPageToken", "nextToken",
    "Count", "TotalCount", "Total", "PageSize",
}

# Params that are NOT resource identifiers — skip when doing dependency wiring
NON_ID_PARAMS = {
    "MaxResults", "MaxItems", "NextToken", "Marker", "StartingToken",
    "PaginationConfig", "Filter", "Filters", "PageSize", "MaxRecords",
    "MaxKeys", "Limit", "PageNumber", "StartTime", "EndTime",
}

# CSPM-priority fields — emitted first so security checks always have what they need.
# Covers: Inventory | Encryption | Access Control | Network | IAM | Logging | Data Security
CSPM_PRIORITY_FIELDS = {
    # ── Inventory / Identity ──
    "Arn", "ResourceArn", "Id", "ResourceId", "Name", "ResourceName",
    "Tags", "Labels", "Region", "Location", "AccountId", "OwnerId",
    "CreationDate", "CreationTime", "CreateTime", "LastModifiedTime",
    "Status", "State", "LifecycleState", "InstanceState",

    # ── Encryption at rest ──
    "Encrypted", "StorageEncrypted", "EncryptionEnabled", "EncryptionType",
    "KmsKeyId", "KMSKeyId", "SseKmsKeyId", "SseType", "ServerSideEncryption",
    "AtRestEncryptionEnabled", "TransitEncryptionEnabled",
    "EncryptionKey", "EncryptionConfig", "EncryptionAtRest",

    # ── Encryption in transit ──
    "TlsPolicy", "MinimumTlsVersion", "EnforceHttps",
    "CACertificateIdentifier", "CertificateDetails",

    # ── Public / Network Access ──
    "PubliclyAccessible", "PublicAccess", "IsPublic", "AllowPublicAccess",
    "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets",
    "PublicIpAddress", "AssociatePublicIpAddress", "MapPublicIpOnLaunch",
    "VpcId", "SubnetId", "SubnetIds", "VpcConfig", "NetworkInterfaces",
    "SecurityGroups", "SecurityGroupIds", "IpPermissions", "IpPermissionsEgress",
    "CidrBlock", "Ipv6CidrBlock", "IngressRules", "EgressRules",

    # ── IAM / Auth ──
    "AssumeRolePolicyDocument", "PolicyDocument", "Policy",
    "PermissionsBoundary", "AttachedManagedPolicies", "InlinePolicies",
    "IamInstanceProfile", "RoleArn", "ServiceRole", "ExecutionRoleArn",
    "IAMDatabaseAuthenticationEnabled", "MFAEnabled", "MfaEnabled",
    "PasswordLastUsed", "PasswordPolicy", "AccessKeys",
    "AssociatedRoles", "IamRoles",

    # ── Logging / Monitoring / Audit ──
    "LoggingEnabled", "EnabledCloudwatchLogsExports", "CloudWatchLogsLogGroupArn",
    "MonitoringInterval", "MonitoringRoleArn", "LogDelivery",
    "ActivityStreamStatus", "ActivityStreamKmsKeyId",
    "EnabledCloudwatchLogsExports", "CloudTrailArn",
    "AuditLogEnabled", "AccessLogging", "ServerAccessLogging",

    # ── High Availability / Backup / Resilience ──
    "MultiAZ", "BackupRetentionPeriod", "DeletionProtection",
    "AutoMinorVersionUpgrade", "AutomaticBackupReplication",
    "SnapshotRetentionLimit", "PreferredBackupWindow",
    "CopyTagsToSnapshot", "PointInTimeRecovery",

    # ── Data Security ──
    "DataClassification", "SensitivityLevel", "Classification",
    "ACL", "BucketPolicy", "ObjectOwnership", "ObjectLockConfiguration",
    "VersioningConfiguration", "VersioningStatus", "MfaDelete",
    "LifecycleConfiguration", "LifecyclePolicies",
    "CrossRegionReplication", "ReplicationConfiguration",

    # ── Compliance / Config ──
    "ComplianceStatus", "ComplianceType", "IsCompliant",
    "DeletionPolicy", "RetentionPolicy", "RetentionPeriod",
}


def _sort_cspm_first(fields: list) -> list:
    """Sort fields: CSPM-priority fields first (alphabetically), then rest (alphabetically)."""
    priority = sorted(f for f in fields if f in CSPM_PRIORITY_FIELDS)
    rest     = sorted(f for f in fields if f not in CSPM_PRIORITY_FIELDS)
    return priority + rest


# Known two-level nested iteration paths.
# AWS sometimes wraps results in a container (e.g., Reservations[].Instances[]).
# The discovery engine's extract_value() supports bracket notation for auto-flattening.
# Format: service → { PascalCase_op → {"path": "Outer[].Inner", "fields": [...]} }
# "fields" is required when step4 doesn't track the inner-level fields.
NESTED_ITEMS_OVERRIDES: dict[str, dict[str, dict]] = {
    "ec2": {
        # describe_instances returns Reservations[] wrapping Instances[].
        # step4 only tracks 6 reservation-level fields, not the instance-level ones.
        "DescribeInstances": {
            "path": "Reservations[].Instances",
            "fields": [
                # Identity / Inventory
                "InstanceId", "InstanceType", "ImageId", "Architecture",
                "Platform", "LaunchTime", "Tags", "KeyName",
                # State
                "State",
                # Network / Access
                "PublicIpAddress", "PrivateIpAddress", "PublicDnsName",
                "VpcId", "SubnetId", "SecurityGroups", "NetworkInterfaces",
                "SourceDestCheck",
                # IAM
                "IamInstanceProfile",
                # Security / Metadata
                "MetadataOptions",    # IMDSv2: HttpTokens=required
                "Monitoring",
                "EbsOptimized",
                # Storage
                "BlockDeviceMappings", "RootDeviceType",
                # Placement
                "Placement",
            ],
        },
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_snake(name: str) -> str:
    """DescribeInstances → describe_instances"""
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    return s.lower()


def _action(op_meta: dict, op_name: str) -> str:
    """Get the boto3 snake_case action for this op (from yaml_action or python_method)."""
    ya = op_meta.get("yaml_action") or op_meta.get("python_method") or ""
    if ya:
        return ya
    return _to_snake(op_name)


def _build_step4_index(step4_path: Path) -> tuple[dict, dict]:
    """
    Returns:
      op_to_fields:     {PascalCase_op → [PascalCase_field, ...]}
      op_to_list_field: {PascalCase_op → list_container_field}
    """
    if not step4_path.exists():
        return {}, {}
    data = json.loads(step4_path.read_text())
    fields = data.get("fields", {})
    op_to_fields: dict = {}
    op_to_list_field: dict = {}
    for fname, fmeta in fields.items():
        if fname in SKIP_FIELDS:
            continue
        if not isinstance(fmeta, dict):
            continue
        ops = fmeta.get("operations", [])
        main_out = fmeta.get("main_output_field", "")
        for op in ops:
            op_to_fields.setdefault(op, []).append(fname)
            if main_out and op not in op_to_list_field:
                op_to_list_field[op] = main_out
    return op_to_fields, op_to_list_field


def _best_parent(entity_field: str, parent_ops: set) -> str:
    """
    Among candidate parent ops, pick the most semantically relevant one.
    Heuristic: prefer root whose op name contains the entity's base name.
    e.g., file_system_id → FileSystem → prefer DescribeFileSystems over DescribeAccessPoints
    """
    # Strip service prefix and convert to PascalCase entity name
    field_name = entity_field.split(".", 1)[-1]           # file_system_id
    entity = re.sub(r"_id$|_arn$|_name$", "", field_name) # file_system
    entity_cc = "".join(p.capitalize() for p in entity.split("_"))  # FileSystem

    for parent in sorted(parent_ops):
        if entity_cc in parent:
            return parent
    return sorted(parent_ops)[0]  # alphabetically first as fallback


def _load_step3_deps(svc_dir: Path, service: str, all_ops: dict) -> dict:
    """
    Parse step3 + step2 to find dependency wiring.
    Returns {dep_op_name: (parent_op_name, [required_params])}.

    Strategy:
      1. step3 roots[] → independent ops and what entity fields they produce
      2. step3 entity_paths[].consumes[op] → non-empty means op is dependent
      3. For each consumed entity field, find best root that produces it → parent
      4. Fallback: for dep ops not in step3, use step2 required_params to find parent
    """
    step3_path = svc_dir / "step3_read_operation_dependency_chain.json"
    if not step3_path.exists():
        return {}
    with open(step3_path) as f:
        data = json.load(f)

    roots = data.get("roots", [])
    entity_paths = data.get("entity_paths", {})

    # root_produces: entity_field → [root_ops that produce it]
    root_prod_list: dict[str, list] = {}
    for root in roots:
        for field in root.get("produces", []):
            root_prod_list.setdefault(field, []).append(root["op"])

    # Convenience: entity_field → best single root_op
    root_produces: dict[str, str] = {
        ef: _best_parent(ef, set(ops))
        for ef, ops in root_prod_list.items()
    }

    # Find: dep_op → set of entity fields it consumes (from step3)
    # entity_paths is indexed by PRODUCED field; consumes[op] lists CONSUMED fields
    op_consumes: dict[str, set] = {}
    for _produced_field, path_list in entity_paths.items():
        for path in path_list:
            for op, consumed_list in path.get("consumes", {}).items():
                if consumed_list:  # non-empty → op consumes these entity fields
                    for cf in consumed_list:
                        op_consumes.setdefault(op, set()).add(cf)

    # Build result: dep_op → (parent_op, req_params)
    result: dict = {}

    # Pass 1: from step3 entity_paths (most reliable)
    for op_name, consumed_fields in op_consumes.items():
        parent_ops: set = set()
        for ef in consumed_fields:
            if ef in root_produces:
                parent_ops.add(root_produces[ef])
        if not parent_ops:
            continue
        # Pick best single parent (prefer most semantically relevant)
        primary_ef = sorted(consumed_fields)[0]
        parent = _best_parent(primary_ef, parent_ops)
        req_params = all_ops.get(op_name, {}).get("required_params", [])
        result[op_name] = (parent, req_params)

    # Step3 service name (entity prefix); may differ from boto3 client name in step2
    # e.g., step2 service="efs" but step3 entity prefix="elasticfilesystem"
    step3_service = data.get("service", service)

    # Pass 2: fallback for dep ops not resolved by step3
    # Use step2 required_params → snake_case → look up in root_produces
    # Only consider real identifier params (skip pagination/filter params)
    for op_name, op_meta in all_ops.items():
        if op_meta.get("independent", False) or op_name in result:
            continue
        req_params = op_meta.get("required_params", [])
        if not req_params:
            continue
        # Filter to identifier params only
        id_params = [p for p in req_params if p not in NON_ID_PARAMS]
        if not id_params:
            continue
        # Try to find parent from any identifier param matching a root's produced field
        for p in id_params:
            snake_p = _to_snake(p)
            for prefix in (step3_service, service):
                entity_key = f"{prefix}.{snake_p}"
                if entity_key in root_produces:
                    result[op_name] = (root_produces[entity_key], req_params)
                    break
            if op_name in result:
                break

    return result


def _find_list_field_step2(output_fields: dict) -> Optional[str]:
    """Fallback: find list-typed field in step2 output_fields."""
    for fname, fmeta in output_fields.items():
        if fname in SKIP_FIELDS:
            continue
        ftype = fmeta.get("type", "") if isinstance(fmeta, dict) else ""
        if ftype == "list":
            return fname
    return None


def _discovery_block(
    op_name: str,
    op_meta: dict,
    service: str,
    op4_fields: dict,
    op4_list_fields: dict,
    step3_deps: dict,
    all_ops: dict,
) -> str:
    """Render one YAML discovery block."""
    action   = _action(op_meta, op_name)
    disc_id  = f"aws.{service}.{action}"
    out_flds = op_meta.get("output_fields", {})

    # List container field: check known nested overrides first, then step2, then step4.
    # Nested overrides handle two-level responses (e.g. Reservations[].Instances).
    nested_override = NESTED_ITEMS_OVERRIDES.get(service, {}).get(op_name)
    if nested_override:
        list_field = nested_override["path"]      # e.g. "Reservations[].Instances"
        override_fields = nested_override.get("fields", [])
    else:
        # Step2 output_fields is most reliable; step4 main_output_field as fallback
        # (Step4 is unreliable for large services: EC2 shares 1200+ fields across ops)
        list_field = _find_list_field_step2(out_flds) or op4_list_fields.get(op_name)
        override_fields = []

    # Item fields: override → step4 → step2 output_fields fallback (get ops only)
    if override_fields:
        item_fields = [f for f in override_fields if f not in SKIP_FIELDS]
    else:
        item_fields = [f for f in op4_fields.get(op_name, []) if f not in SKIP_FIELDS]
        if not item_fields and not list_field:
            # Fallback: top-level output fields (get ops)
            item_fields = [f for f in out_flds if f not in SKIP_FIELDS]
    item_fields = _sort_cspm_first(item_fields)

    # Dependency info from step3
    dep_info = step3_deps.get(op_name)

    lines = [f"  # ── {op_name} ──"]
    lines.append(f"  - discovery_id: {disc_id}")

    # Wire for_each only when op has real identifier params (not just pagination)
    real_id_params = [p for p in (op_meta.get("required_params") or [])
                      if p not in NON_ID_PARAMS]
    if dep_info and real_id_params:
        parent_op, req_params = dep_info
        parent_action = _action(all_ops.get(parent_op, {}), parent_op)
        parent_disc_id = f"aws.{service}.{parent_action}"
        lines.append(f"    for_each: {parent_disc_id}")

    lines.append(f"    calls:")
    lines.append(f"      - action: {action}")

    # Inject params for dependent ops (only real identifier params)
    if dep_info and real_id_params:
        lines.append(f"        params:")
        for p in real_id_params:
            lines.append(f"          {p}: '{{{{ item.{p} }}}}'")

    lines.append(f"        save_as: response")
    lines.append(f"        on_error: continue")
    lines.append(f"    emit:")
    lines.append(f"      as: item")

    if list_field:
        lines.append(f"      items_for: '{{{{ response.{list_field} }}}}'")
        if item_fields:
            lines.append(f"      item:")
            for fname in item_fields:
                lines.append(f"        {fname}: '{{{{ item.{fname} }}}}'")
    elif item_fields:
        # Single-item response (get op)
        lines.append(f"      item:")
        for fname in item_fields:
            lines.append(f"        {fname}: '{{{{ response.{fname} }}}}'")

    return "\n".join(lines)


def build_step6(svc_dir: Path) -> Optional[str]:
    read2_path = svc_dir / "step2_read_operation_registry.json"
    step4_path = svc_dir / "step4_fields_produced_index.json"

    if not read2_path.exists():
        return None

    read2   = json.loads(read2_path.read_text())
    service = read2.get("service", svc_dir.name)
    ops     = read2.get("operations", {})

    if not ops:
        return None

    op4_fields, op4_list_fields = _build_step4_index(step4_path)
    step3_deps = _load_step3_deps(svc_dir, service, ops)

    ind_ops = {n: m for n, m in ops.items() if m.get("independent", False)}
    dep_ops = {n: m for n, m in ops.items() if not m.get("independent", False)}

    now = _now()
    header = textwrap.dedent(f"""\
        # ============================================================
        # Discovery YAML — {service} (AWS)
        # Generated: {now}
        # Actions use boto3 SDK snake_case method names
        # ============================================================
        version: '1.0'
        provider: aws
        service: {service}
        services:
          client: {service}
          module: boto3.client
        discovery:
        """)

    blocks = []
    for op_name in sorted(ind_ops):
        blocks.append(_discovery_block(
            op_name, ind_ops[op_name], service,
            op4_fields, op4_list_fields, step3_deps, ops
        ))

    if dep_ops:
        blocks.append("  # ── Dependent read operations (require identifiers) ──")
        for op_name in sorted(dep_ops):
            blocks.append(_discovery_block(
                op_name, dep_ops[op_name], service,
                op4_fields, op4_list_fields, step3_deps, ops
            ))

    return header + "\n".join(blocks) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Generate step6 discovery YAML for AWS services (boto3 snake_case)"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Report without writing files")
    parser.add_argument("--service", default=None,
                        help="Only process one service (e.g., elasticfilesystem)")
    args = parser.parse_args()

    if args.service:
        svc_dirs = [AWS_ROOT / args.service]
    else:
        svc_dirs = sorted(
            d for d in AWS_ROOT.iterdir()
            if d.is_dir() and d.name not in SKIP
            and (d / "step2_read_operation_registry.json").exists()
        )

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"AWS step6 generation ({mode}): {len(svc_dirs)} service(s)")
    print()

    written = skipped = total_ops = dep_wired = 0
    for svc_dir in svc_dirs:
        if not svc_dir.exists():
            print(f"  {svc_dir.name}: NOT FOUND — skipping")
            skipped += 1
            continue

        content = build_step6(svc_dir)
        if content is None:
            skipped += 1
            continue

        read2  = json.loads((svc_dir / "step2_read_operation_registry.json").read_text())
        ops    = read2.get("operations", {})
        step4_path = svc_dir / "step4_fields_produced_index.json"
        op4f, op4l = _build_step4_index(step4_path)
        step3d = _load_step3_deps(svc_dir, svc_dir.name, ops)

        n_ops  = len(ops)
        n_dep  = sum(1 for m in ops.values() if not m.get("independent", False))
        n_wired = sum(1 for op in ops if op in step3d)
        n_fields = sum(1 for op in ops if op4f.get(op) or op4l.get(op))

        action = "Would write" if args.dry_run else "Written   "
        print(f"  {svc_dir.name:<45} {action}: {n_ops:>4} ops "
              f"({n_wired:>3}/{n_dep} dep wired, {n_fields:>4} with fields)")

        if not args.dry_run:
            out_path = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
            out_path.write_text(content)

        written    += 1
        total_ops  += n_ops
        dep_wired  += n_wired

    print()
    print(f"Done: {written} written, {skipped} skipped")
    print(f"Total: {total_ops} ops, {dep_wired} dependent ops with for_each wired")


if __name__ == "__main__":
    main()
