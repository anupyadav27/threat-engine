#!/usr/bin/env python3
"""
Generate step6_{service}.discovery.yaml for OCI from step2 + step4.

OCI Python SDK response format:
  list ops: response.data is a list of model objects
             → items_for: '{{ response.data }}'
             → item fields: '{{ item.FIELD }}'
  get  ops: response.data is a single model object
             → no items_for
             → item fields: '{{ response.data.FIELD }}'

Field sources (priority order):
  1. step4 fields_produced_index (correctly typed by kind)
  2. step2 output_fields keys (fallback)

Usage:
    python3 data_pythonsdk/scripts/generate_oci_step6.py
    python3 data_pythonsdk/scripts/generate_oci_step6.py --dry-run
"""

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path

OCI_ROOT = Path(__file__).parent.parent / "oci"
SKIP = {"tools", "__pycache__", "temp_code"}

READ_KINDS = {"read_list", "read_get"}

SKIP_FIELDS = {
    "opc_next_page", "opc_request_id", "opc_client_request_id",
    "next_page", "page", "next", "limit",
    "total_count", "total", "count", "offset",
}

# CSPM-priority fields (snake_case for OCI SDK) — emitted first
CSPM_PRIORITY_FIELDS = {
    # Inventory / Identity
    "id", "name", "display_name", "compartment_id", "tenancy_id",
    "lifecycle_state", "time_created", "freeform_tags", "defined_tags",
    # Encryption
    "kms_key_id", "is_kms_key_version_used", "encryption_key",
    "are_legacy_okv_auths_disabled",
    # Access / Network
    "is_public", "is_database_management_enabled",
    "vcn_id", "subnet_id", "nsg_ids", "security_list_ids",
    "ingress_security_rules", "egress_security_rules",
    "allowed_ips", "cidr_block",
    # IAM / Auth
    "principal_name", "is_mfa_activated", "user_id",
    "compartment_id", "permission", "policies",
    # Logging / Monitoring
    "is_unified_auditing_enabled", "log_group_id",
    "audit_retention_period_in_days", "is_atp_enabled",
    # HA / Backup
    "is_auto_backup_enabled", "backup_retention_period_in_days",
    "is_dataguard_enabled", "data_guard_region_type",
    "deletion_protection",
    # Data Security
    "is_object_event_enabled", "versioning",
    "replication_policy", "object_lifecycle_policy_etag",
}


def _sort_cspm_first(fields: list) -> list:
    priority = sorted(f for f in fields if f in CSPM_PRIORITY_FIELDS)
    rest     = sorted(f for f in fields if f not in CSPM_PRIORITY_FIELDS)
    return priority + rest


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_step2_ops(svc_dir: Path) -> dict:
    """Load step2 read ops: {op_key: op_meta}."""
    step2 = svc_dir / "step2_read_operation_registry.json"
    if not step2.exists():
        return {}
    with open(step2) as f:
        data = json.load(f)
    return {
        k: v for k, v in data.get("operations", {}).items()
        if v.get("kind", "") in READ_KINDS
    }


def _load_step4_op_fields(svc_dir: Path) -> dict[str, list[str]]:
    """
    Returns {op_key: [field_name, ...]} from step4, filtering by op kind:
      - list ops get fields from items[].field_name paths
      - get  ops get fields from flat field_name paths
    """
    step4 = svc_dir / "step4_fields_produced_index.json"
    if not step4.exists():
        return {}
    with open(step4) as f:
        data = json.load(f)

    result: dict[str, list[str]] = {}
    for field_path, field_data in data.get("fields", {}).items():
        is_list_field = "[]." in field_path
        field_name = field_path.split("[].")[-1] if is_list_field else field_path
        if not field_name or field_name in SKIP_FIELDS:
            continue

        for producer in field_data.get("producers", []):
            op_key = producer.get("op", "")
            kind = producer.get("kind", "")
            if not op_key:
                continue
            # Match field type to op kind
            if is_list_field and kind == "read_list":
                result.setdefault(op_key, []).append(field_name)
            elif not is_list_field and kind == "read_get":
                result.setdefault(op_key, []).append(field_name)

    return result


def _get_item_fields(op_key: str, kind: str, op_meta: dict,
                     step4_fields: dict) -> list[str]:
    """Get CSPM-relevant fields for this op, deduped and sorted."""
    # Primary: step4 (properly typed by kind)
    if op_key in step4_fields:
        return sorted(set(step4_fields[op_key]))

    # Fallback: step2 output_fields keys
    out = op_meta.get("output_fields", {})
    if out:
        return sorted(f for f in out.keys() if f not in SKIP_FIELDS)

    return []


def _render_block(op_key: str, op: dict, service: str,
                  step4_fields: dict) -> str:
    action     = op.get("yaml_action", op_key)
    disc_id    = f"oci.{service}.{op_key}"
    kind       = op.get("kind", "read_get")
    ind        = op.get("independent", False)
    req_params = op.get("required_params", [])
    label      = " [dependent]" if not ind else ""

    item_fields = _sort_cspm_first(_get_item_fields(op_key, kind, op, step4_fields))

    lines = [
        f"  # ── {op_key}{label} ──",
        f"  - discovery_id: {disc_id}",
        f"    calls:",
        f"      - action: {action}",
        f"        save_as: response",
        f"        on_error: continue",
        f"    emit:",
        f"      as: item",
    ]

    if kind == "read_list":
        # OCI list ops: response.data is a list of model objects
        lines.append("      items_for: '{{ response.data }}'")
        if item_fields:
            lines.append("      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ item.{field} }}}}'")
    else:
        # OCI get ops: response.data is a single model object
        if item_fields:
            lines.append("      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ response.data.{field} }}}}'")

    if req_params:
        lines.append(f"    # required_params: {req_params}")

    return "\n".join(lines)


def build_step6_yaml(svc_dir: Path) -> str | None:
    service = svc_dir.name
    ops = _load_step2_ops(svc_dir)
    if not ops:
        return None

    step4_fields = _load_step4_op_fields(svc_dir)

    now = _now()
    header = textwrap.dedent(f"""\
        # Discovery YAML — {service} (OCI)
        # Generated: {now}
        version: '1.0'
        provider: oci
        service: {service}
        services:
          client: {service}
          module: oci.{service}
        discovery:
        """)

    ind_ops = {k: v for k, v in ops.items() if v.get("independent", False)}
    dep_ops = {k: v for k, v in ops.items() if not v.get("independent", False)}

    blocks: list[str] = []
    if ind_ops:
        blocks += [_render_block(k, v, service, step4_fields)
                   for k, v in sorted(ind_ops.items())]
    if dep_ops:
        if blocks:
            blocks.append("  # ── Dependent ops ──")
        blocks += [_render_block(k, v, service, step4_fields)
                   for k, v in sorted(dep_ops.items())]

    if not blocks:
        return None

    return header + "\n".join(blocks) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Generate step6 discovery YAML for all OCI services"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Report without writing files")
    args = parser.parse_args()

    svc_dirs = sorted(d for d in OCI_ROOT.iterdir()
                      if d.is_dir() and d.name not in SKIP)
    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"OCI step6 generation ({mode}): {len(svc_dirs)} service directories")
    print()

    written = skipped = with_fields = 0
    for svc_dir in svc_dirs:
        yaml_content = build_step6_yaml(svc_dir)
        if not yaml_content:
            skipped += 1
            continue

        ops = _load_step2_ops(svc_dir)
        step4 = _load_step4_op_fields(svc_dir)
        n_ops = len(ops)
        n_with_fields = sum(1 for k, v in ops.items()
                            if _get_item_fields(k, v.get("kind", ""), v, step4))

        action = "Would write" if args.dry_run else "Written   "
        print(f"  {svc_dir.name:<50} {action}: {n_ops} ops, {n_with_fields} with fields")

        if not args.dry_run:
            out_path = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
            out_path.write_text(yaml_content)

        written += 1
        with_fields += n_with_fields

    print()
    print(f"Done: {written} written, {skipped} skipped, {with_fields} total ops with fields")


if __name__ == "__main__":
    main()
