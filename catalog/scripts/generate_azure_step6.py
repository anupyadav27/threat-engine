#!/usr/bin/env python3
"""
Generate step6_{service}.discovery.yaml for Azure from step2 + step4.

Converts existing REST API camelCase action names (listBySubscription)
to Azure Python SDK snake_case names (list_by_subscription).

Azure SDK response format:
  list ops: response.value is a list (standard Azure SDK/REST pattern)
             → items_for: '{{ response.value }}'
             → item fields: '{{ item.FIELD }}'
  get  ops: direct field access on the response object
             → no items_for
             → item fields: '{{ response.FIELD }}'

Field sources (priority order):
  1. step2 item_fields (Azure stores rich per-item field schema in step2)
  2. step4 fields_produced_index (kind-aware field paths)

Dependency chain (for_each + params):
  Azure step3 has different format than GCP — not used by this generator yet.
  All ops that have required_params are marked [dependent] but without for_each wiring.

Usage:
    python3 data_pythonsdk/scripts/generate_azure_step6.py
    python3 data_pythonsdk/scripts/generate_azure_step6.py --dry-run
    python3 data_pythonsdk/scripts/generate_azure_step6.py --service compute
"""

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path

AZURE_ROOT = Path(__file__).parent.parent / "azure"
SKIP = {"tools", "__pycache__", "temp_code"}

READ_KINDS = {"read_list", "read_get"}

# Azure SDK standard pagination/metadata fields — skip from emit
SKIP_FIELDS = {
    "next_link", "next_page_link", "odataNextLink", "@odata.nextLink",
    "count", "total_count", "odataCount", "@odata.count",
    "odataContext", "@odata.context", "etag",
}

# CSPM-priority fields (snake_case for Azure SDK) — emitted first
CSPM_PRIORITY_FIELDS = {
    # Inventory / Identity
    "id", "name", "type", "location", "tags", "resource_group", "subscription_id",
    "provisioning_state", "status",
    # Encryption
    "encryption", "encryption_settings", "kms_key_source", "kms_key_id",
    "key_vault_properties", "server_side_encryption", "tls_min_version",
    "minimum_tls_version", "enable_https_traffic_only", "encryption_at_rest",
    # Access / Network
    "public_network_access", "allow_public_access", "public_access",
    "network_rule_set", "network_acls", "firewall_rules", "virtual_network_rules",
    "bypass", "default_action", "public_ip_address", "private_endpoint_connections",
    "enable_rbac_authorization",
    # IAM / Auth
    "identity", "managed_identity", "principal_id", "role_assignments",
    "object_id", "client_id", "mfa_type", "mfa_enabled",
    # Logging / Monitoring
    "audit_log_destination", "diagnostic_settings", "log_analytics_workspace_id",
    "audit_policies", "enable_audit", "storage_endpoint",
    # HA / Backup
    "zone_redundant", "geo_redundant_backup", "backup_retention_days",
    "deletion_protection", "geo_replication",
    # Data Security
    "blob_service_properties", "container_delete_retention_policy",
    "cors_rules", "allow_cross_tenant_replication",
}


def _sort_cspm_first(fields: list) -> list:
    """Sort fields: CSPM-priority first (alphabetically), then rest (alphabetically)."""
    priority = sorted(f for f in fields if f in CSPM_PRIORITY_FIELDS)
    rest     = sorted(f for f in fields if f not in CSPM_PRIORITY_FIELDS)
    return priority + rest


# Universal Azure ARM base fields emitted when an operation has NO field data at all.
# Every Azure Resource Manager resource inherits these from the ARM base resource contract.
# Covers core CSPM needs: identity, inventory, encryption, network access, IAM.
AZURE_ARM_BASE_FIELDS: list[str] = [
    # Inventory / Identity (ARM required on every resource)
    "id", "name", "type", "location", "tags",
    "etag", "kind", "sku", "zones", "plan",
    # State
    "provisioning_state",
    # Managed identity (assigned at ARM level, not in properties)
    "identity",
    # Security-relevant ARM-level fields (present on most resources)
    "properties",           # raw properties bag when individual fields aren't known
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_step2_ops(svc_dir: Path) -> dict:
    """
    Load step2 READ ops.
    Azure step2 already uses SDK snake_case for operation keys and yaml_action.
    item_fields may be a dict {field: {type, ...}} or empty list [].
    """
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
    Returns {op_key: [field_name, ...]} from step4, plus two sentinel keys:
      "_list_fallback" → fields from step4 seed_from_list (for read_list ops with no other data)
      "_get_fallback"  → fields from step4 enriched_from_get_describe (for read_get ops)

    Azure step4 format differs from other CSPs: it has no per-op "producers" structure.
    Instead it provides a global service field pool split by list vs get:
      seed_from_list           → fields seen in list responses
      enriched_from_get_describe → additional fields from get/describe responses
    """
    step4 = svc_dir / "step4_fields_produced_index.json"
    if not step4.exists():
        return {}
    with open(step4) as f:
        data = json.load(f)

    result: dict[str, list[str]] = {}

    # Per-op linkage (present in some Azure step4 files that use producers format)
    for field_path, field_data in data.get("fields", {}).items():
        if not isinstance(field_data, dict):
            continue
        is_list_field = "[]." in field_path
        field_name = field_path.split("[].")[-1] if is_list_field else field_path
        if not field_name or field_name in SKIP_FIELDS:
            continue
        for producer in field_data.get("producers", []):
            op_key = producer.get("op", "")
            kind = producer.get("kind", "")
            if not op_key:
                continue
            if is_list_field and kind == "read_list":
                result.setdefault(op_key, []).append(field_name)
            elif not is_list_field and kind == "read_get":
                result.setdefault(op_key, []).append(field_name)

    # Service-wide fallback buckets (always populated from the global pool)
    def _clean(lst) -> list[str]:
        return sorted(f for f in (lst or []) if f and f not in SKIP_FIELDS)

    result["_list_fallback"] = _clean(data.get("seed_from_list", []))
    result["_get_fallback"]  = _clean(
        data.get("enriched_from_get_describe", []) or data.get("seed_from_list", [])
    )

    return result


def _get_item_fields(op_key: str, kind: str, op_meta: dict,
                     step4_fields: dict) -> list[str]:
    """
    Get CSPM-relevant fields for this op.
    Priority: step2 item_fields → step4 per-op → step2 output_fields
              → step4 service-wide fallback (seed_from_list / enriched_from_get_describe).
    """
    # Primary: step2 item_fields (Azure stores rich schema here)
    item_flds = op_meta.get("item_fields", [])
    if isinstance(item_flds, dict) and item_flds:
        return sorted(f for f in item_flds.keys() if f not in SKIP_FIELDS)
    elif isinstance(item_flds, list) and item_flds:
        return sorted(f for f in item_flds if f not in SKIP_FIELDS)

    # Secondary: step4 per-op kind-aware fields
    if op_key in step4_fields:
        return sorted(set(step4_fields[op_key]))

    # Tertiary: step2 output_fields filtered
    out = op_meta.get("output_fields", {})
    if isinstance(out, dict) and out:
        return sorted(f for f in out.keys() if f not in SKIP_FIELDS)
    elif isinstance(out, list) and out:
        return sorted(f for f in out if f not in SKIP_FIELDS)

    # step4 service-wide field pool (split by op kind)
    fallback_key = "_list_fallback" if kind == "read_list" else "_get_fallback"
    svc_wide = step4_fields.get(fallback_key, [])
    if svc_wide:
        return svc_wide

    # Absolute last resort: universal Azure ARM base fields.
    # Every ARM resource has id/name/location/tags/identity/provisioning_state.
    # Emitting these ensures at least basic inventory + CSPM fields are captured
    # even when SDK introspection failed to record the operation's return schema.
    return AZURE_ARM_BASE_FIELDS


def _render_block(op_key: str, op: dict, service: str,
                  step4_fields: dict) -> str:
    """
    Render a single discovery YAML block.
    action uses SDK snake_case (from yaml_action or op_key directly).
    Azure list ops: items_for: '{{ response.value }}' (standard Azure SDK).
    """
    action     = op.get("yaml_action", op_key)
    disc_id    = f"azure.{service}.{op_key}"
    kind       = op.get("kind", "read_get")
    ind        = op.get("independent", False)
    req_params = op.get("required_params", [])
    label      = " [dependent]" if not ind else ""

    # Collect main_output_field for list ops (usually "value" in Azure)
    main_out   = op.get("main_output_field") or "value"
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
        # Azure SDK list ops: response.value contains the items list
        lines.append(f"      items_for: '{{{{ response.{main_out} }}}}'")
        if item_fields:
            lines.append("      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ item.{field} }}}}'")
    else:
        # Azure SDK get ops: direct field access on response
        if item_fields:
            lines.append("      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ response.{field} }}}}'")

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
        # Discovery YAML — {service} (Azure)
        # Generated: {now}
        # Actions use Azure Python SDK snake_case names (azure-mgmt-*)
        version: '1.0'
        provider: azure
        service: {service}
        services:
          client: {service}
          module: azure.mgmt.{service}
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
        description="Generate step6 discovery YAML for Azure (SDK snake_case names)"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Report without writing files")
    parser.add_argument("--service", default=None,
                        help="Only process one service (e.g., compute)")
    args = parser.parse_args()

    if args.service:
        svc_dirs = [AZURE_ROOT / args.service]
    else:
        svc_dirs = sorted(d for d in AZURE_ROOT.iterdir()
                          if d.is_dir() and d.name not in SKIP)

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"Azure step6 generation ({mode}): {len(svc_dirs)} service(s)")
    print()

    written = skipped = total_ops = ops_with_fields = 0
    for svc_dir in svc_dirs:
        if not svc_dir.exists():
            print(f"  {svc_dir.name}: NOT FOUND — skipping")
            skipped += 1
            continue

        yaml_content = build_step6_yaml(svc_dir)
        if not yaml_content:
            skipped += 1
            continue

        ops = _load_step2_ops(svc_dir)
        step4 = _load_step4_op_fields(svc_dir)
        n_ops = len(ops)
        n_with_fields = sum(
            1 for k, v in ops.items()
            if _get_item_fields(k, v.get("kind", ""), v, step4)
        )

        action = "Would write" if args.dry_run else "Written   "
        print(f"  {svc_dir.name:<45} {action}: {n_ops:>4} ops, {n_with_fields:>4} with fields")

        if not args.dry_run:
            out_path = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
            out_path.write_text(yaml_content)

        written += 1
        total_ops += n_ops
        ops_with_fields += n_with_fields

    pct = f"{ops_with_fields/total_ops*100:.1f}%" if total_ops else "n/a"
    print()
    print(f"Done: {written} written, {skipped} skipped")
    print(f"Total: {total_ops} ops, {ops_with_fields} with fields ({pct})")


if __name__ == "__main__":
    main()
