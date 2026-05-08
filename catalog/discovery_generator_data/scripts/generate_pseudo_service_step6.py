#!/usr/bin/env python3
"""
generate_pseudo_service_step6.py

For each of the 14 new check-engine pseudo-services (msk, custom, event, etc.),
reads the check engine's discoveries.yaml, looks up field maps from the real
service's step4_fields_produced_index.json, resolves dependency params from
step3_read_operation_dependency_chain.json, then writes:

  catalog/python_field_generator/aws/<pseudo_svc>/
    step6_<pseudo_svc>_discoveries_minimum.yaml

Format matches other step6 minimum files: explicit emit.item field mappings,
for_each wiring, items_for from step4 main_output_field.

Pseudo-service → real catalog directory mapping:
  msk              → kafka         (client: kafka)
  custom           → events        (client: events)
  event            → cloudtrail    (client: cloudtrail)
  eventschemas     → schemas       (client: schemas)
  iotdevicedefender→ iot           (client: iot)
  acmpca           → acm-pca       (client: acm-pca)
  service          → servicecatalog(client: servicecatalog)
  customerprofiles → customer-profiles (client: customer-profiles)
  codegurureviewer → codeguru-reviewer (client: codeguru-reviewer)
  approved         → ec2           (client: ec2)
  desired          → ec2           (client: ec2)
  required         → resourcegroupstaggingapi (client: resourcegroupstaggingapi)
  s3express        → s3            (client: s3)
  virtualmachine   → backup        (client: backup-gateway)

Usage:
    python3 generate_pseudo_service_step6.py              # all 14 services
    python3 generate_pseudo_service_step6.py --service msk
    python3 generate_pseudo_service_step6.py --dry-run
"""

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE = Path(__file__).resolve().parent.parent          # catalog/python_field_generator
AWS_ROOT = BASE / "aws"
CHECK_SERVICES = BASE.parent.parent / "engines" / "check" / "engine_check_aws" / "services"

# pseudo_svc → (catalog_dir_name, boto3_client_name)
PSEUDO_MAP: dict[str, tuple[str, str]] = {
    "msk":               ("kafka",                    "kafka"),
    "custom":            ("events",                   "events"),
    "event":             ("cloudtrail",               "cloudtrail"),
    "eventschemas":      ("schemas",                  "schemas"),
    "iotdevicedefender": ("iot",                      "iot"),
    "acmpca":            ("acm-pca",                  "acm-pca"),
    "service":           ("servicecatalog",            "servicecatalog"),
    "customerprofiles":  ("customer-profiles",         "customer-profiles"),
    "codegurureviewer":  ("codeguru-reviewer",         "codeguru-reviewer"),
    "approved":          ("ec2",                       "ec2"),
    "desired":           ("ec2",                       "ec2"),
    "required":          ("resourcegroupstaggingapi",  "resourcegroupstaggingapi"),
    "s3express":         ("s3",                        "s3"),
    "virtualmachine":    ("backup-gateway",              "backup-gateway"),
}

# Fields to omit from emit.item (pagination / response metadata)
SKIP_FIELDS = {
    "NextToken", "Marker", "IsTruncated", "NextMarker", "ResponseMetadata",
    "ContinuationToken", "PageToken", "MaxResults", "RequestId", "nextToken",
    "Count", "TotalCount", "Total", "PageSize", "MaxRecords",
    "PaginationToken", "NextPageToken",
}

# Special-case items_for overrides for ops with nested list structures
SPECIAL_ITEMS_FOR: dict[str, str] = {
    "DescribeInstances": "{{ response.Reservations[].Instances }}",
}

# CSPM-priority fields emit first
CSPM_PRIORITY = {
    "Arn", "ResourceArn", "Id", "ResourceId", "Name", "ResourceName",
    "Tags", "Labels", "Status", "State", "Enabled", "Active",
    "CreationTime", "CreationDate", "CreateTime", "LastModifiedTime",
    "Encrypted", "KmsKeyId", "EncryptionInfo", "EncryptionInTransit",
    "EncryptionAtRest", "EnhancedMonitoring", "PubliclyAccessible",
    "Policy", "AllowProfileCreation", "ClientAuthentication",
    "VpcId", "SubnetIds", "SecurityGroups", "LoggingInfo", "logDelivery",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def to_pascal(snake: str) -> str:
    """list_clusters_v2  →  ListClustersV2"""
    return "".join(w.title() for w in snake.split("_"))


def _sort_fields(fields: list[str]) -> list[str]:
    """CSPM-priority fields first, then alphabetical."""
    priority = [f for f in fields if f in CSPM_PRIORITY]
    rest = sorted(f for f in fields if f not in CSPM_PRIORITY)
    return priority + rest


# ── Step4 / Step3 loaders ──────────────────────────────────────────────────────

def load_step4(catalog_dir: Path) -> tuple[dict[str, list], dict[str, str]]:
    """
    Returns:
        op_to_fields : { PascalOp → [ {name, main_output_field} ] }
        entity_to_field: { entity_key → PascalCase field name }
    """
    p = catalog_dir / "step4_fields_produced_index.json"
    if not p.exists():
        return {}, {}
    data = json.loads(p.read_text())
    raw_fields = data.get("fields", {})

    op_to_fields: dict[str, list] = {}
    entity_to_field: dict[str, str] = {}

    for fname, finfo in raw_fields.items():
        entity = finfo.get("dependency_index_entity", "")
        if entity:
            entity_to_field[entity] = fname

        mof = finfo.get("main_output_field", "")
        for op in finfo.get("operations", []):
            op_to_fields.setdefault(op, []).append({"name": fname, "mof": mof})

    return op_to_fields, entity_to_field


def load_step2(catalog_dir: Path) -> dict[str, dict]:
    """Returns {PascalOp: {output_fields: {key: ...}, required_params: [...], ...}}"""
    p = catalog_dir / "step2_read_operation_registry.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    return data.get("operations", data)


def load_step3_consumes(catalog_dir: Path) -> dict[str, list[str]]:
    """
    Returns { PascalOp → [entity, ...] } — the entities each op CONSUMES (its inputs).
    """
    p = catalog_dir / "step3_read_operation_dependency_chain.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    op_consumes: dict[str, set] = {}
    for _entity, paths in data.get("entity_paths", {}).items():
        for path in paths:
            for op, consumed_list in path.get("consumes", {}).items():
                if consumed_list:
                    op_consumes.setdefault(op, set()).update(consumed_list)
    return {op: sorted(ents) for op, ents in op_consumes.items()}


# ── Load check discoveries.yaml ────────────────────────────────────────────────

def load_check_discoveries(pseudo_svc: str) -> list[dict]:
    """Parse the check engine's discoveries.yaml for a pseudo-service."""
    import yaml  # local import — not everyone has pyyaml globally
    p = CHECK_SERVICES / pseudo_svc / "discoveries" / f"{pseudo_svc}.discoveries.yaml"
    if not p.exists():
        return []
    with open(p) as f:
        data = yaml.safe_load(f)
    return data.get("discovery", [])


# ── items_for / emit-field resolution ─────────────────────────────────────────

def _resolve_items_for_and_fields(
    pascal: str,
    op_registry: Optional[dict],
    op_to_fields: dict,
) -> tuple[str, list[str]]:
    """Return (items_for_expr, sorted_field_names) for one op.

    Strategy:
      1. Special-case overrides (e.g. DescribeInstances nested list)
      2. Step2 output_fields (authoritative per-op containers)
         - 0 non-skip keys          → flat response  → items_for={{ response }}
         - 1 non-skip key           → single container → items_for={{ response.Key }}
         - 2-3 non-skip keys        → use first non-skip key as container
         - 4+ non-skip keys         → flat describe response → items_for={{ response }}
      3. Step4 mof_votes fallback
      4. {{ response }} as last resort
    For flat responses the step2 output_fields keys are used as emit fields;
    for container responses step4 op_to_fields are used.
    """
    # 1. Special-case overrides
    if pascal in SPECIAL_ITEMS_FOR:
        items_for = SPECIAL_ITEMS_FOR[pascal]
        # Emit fields from step4 for special-case ops
        op_fields_info = op_to_fields.get(pascal, [])
        field_names_raw = [fi["name"] for fi in op_fields_info if fi["name"] not in SKIP_FIELDS]
        return items_for, _sort_fields(list(dict.fromkeys(field_names_raw)))

    is_flat = False
    items_for: Optional[str] = None
    step2_flat_fields: list[str] = []

    # 2. Step2 output_fields
    if op_registry and pascal in op_registry:
        out_keys = [k for k in op_registry[pascal].get("output_fields", {})
                    if k not in SKIP_FIELDS]
        if len(out_keys) == 0:
            items_for = "{{ response }}"
            is_flat = True
        elif len(out_keys) == 1:
            items_for = f"{{{{ response.{out_keys[0]} }}}}"
        elif len(out_keys) >= 4:
            # Many non-skip keys = individual fields, not container names
            items_for = "{{ response }}"
            is_flat = True
            step2_flat_fields = out_keys
        else:
            # 2-3 non-skip keys: treat first as the data container
            items_for = f"{{{{ response.{out_keys[0]} }}}}"

    # 3. Step4 mof_votes fallback
    if items_for is None:
        op_fields_info = op_to_fields.get(pascal, [])
        mof_votes: dict[str, int] = {}
        for fi in op_fields_info:
            mof = fi.get("mof", "")
            if mof:
                mof_votes[mof] = mof_votes.get(mof, 0) + 1
        if mof_votes:
            items_for = f"{{{{ response.{max(mof_votes, key=mof_votes.get)} }}}}"
        else:
            items_for = "{{ response }}"
            is_flat = True

    # Emit field names
    if is_flat and step2_flat_fields:
        field_names = _sort_fields(step2_flat_fields)
    else:
        op_fields_info = op_to_fields.get(pascal, [])
        field_names_raw = [fi["name"] for fi in op_fields_info if fi["name"] not in SKIP_FIELDS]
        field_names = _sort_fields(list(dict.fromkeys(field_names_raw)))

    # Remove the container key itself from field_names
    # (step4 sometimes indexes the list container as a field rather than its members)
    if items_for and "response." in items_for:
        container_key = items_for.split("response.")[1].rstrip(" }").split("[")[0]
        field_names = [f for f in field_names if f != container_key]

    return items_for, field_names


# ── Build a single discovery block ────────────────────────────────────────────

def build_block(
    action: str,
    pseudo_svc: str,
    op_to_fields: dict,
    entity_to_field: dict,
    op_consumes: dict,
    params_from_yaml: Optional[dict] = None,
    parent_action: Optional[str] = None,
    calls_params_from_yaml: Optional[dict] = None,
    discovery_id: Optional[str] = None,
    op_registry: Optional[dict] = None,
) -> dict:
    """Build one discovery block dict, ready for YAML serialisation.

    Args:
        action: boto3 snake_case action (e.g. list_clusters_v2)
        pseudo_svc: service name for fallback discovery_id (e.g. msk)
        discovery_id: exact discovery_id from check YAML (preferred over derived)
        op_registry: step2 operation registry for accurate items_for resolution
        parent_action: if dependent op, the parent snake_case action
        calls_params_from_yaml: params dict from the check discoveries.yaml
    """
    pascal = to_pascal(action)
    disc_id = discovery_id or f"aws.{pseudo_svc}.{action}"

    # ── Params for the API call ──
    call_params: dict = {}

    # 1. Use params already defined in the check YAML (highest fidelity)
    if calls_params_from_yaml:
        call_params = calls_params_from_yaml

    # 2. Fall back to step3 entity consumption → field name lookup
    elif parent_action:
        consumed = op_consumes.get(pascal, [])
        for entity in consumed:
            field = entity_to_field.get(entity)
            if field:
                call_params[field] = f"{{{{ item.{field} }}}}"

    # ── items_for + emit fields (step2 → step4 fallback) ──
    items_for, field_names = _resolve_items_for_and_fields(pascal, op_registry, op_to_fields)
    emit_item = {fname: f"{{{{ item.{fname} }}}}" for fname in field_names}

    # ── Assemble ──
    call_block: dict = {"action": action, "save_as": "response", "on_error": "continue"}
    if call_params:
        call_block["params"] = call_params

    block: dict = {
        "discovery_id": disc_id,
        "calls": [call_block],
        "emit": {"as": "item", "items_for": items_for, "item": emit_item},
    }
    if parent_action:
        block["for_each"] = f"aws.{pseudo_svc}.{parent_action}"

    return block


# ── YAML writer ────────────────────────────────────────────────────────────────

def _yaml_str(value) -> str:
    """Wrap template strings in single quotes; pass through non-strings as-is."""
    if not isinstance(value, str):
        return str(value)
    if "{{" in value:
        return f"'{value}'"
    return value


def _write_block(lines: list[str], block: dict, indent: int = 2) -> None:
    """Serialise one discovery block to YAML lines."""
    pad = " " * indent
    pad2 = " " * (indent + 2)
    pad3 = " " * (indent + 4)
    pad4 = " " * (indent + 6)

    lines.append(f"{pad}- discovery_id: {block['discovery_id']}")

    if "for_each" in block:
        lines.append(f"{pad2}for_each: {block['for_each']}")

    lines.append(f"{pad2}calls:")
    for call in block["calls"]:
        lines.append(f"{pad2}- action: {call['action']}")
        lines.append(f"{pad3}save_as: {call['save_as']}")
        lines.append(f"{pad3}on_error: {call['on_error']}")
        if call.get("params"):
            lines.append(f"{pad3}params:")
            for k, v in call["params"].items():
                lines.append(f"{pad4}{k}: {_yaml_str(v)}")

    emit = block["emit"]
    lines.append(f"{pad2}emit:")
    lines.append(f"{pad3}as: {emit['as']}")
    lines.append(f"{pad3}items_for: {_yaml_str(emit['items_for'])}")
    if emit.get("item"):
        lines.append(f"{pad3}item:")
        for k, v in emit["item"].items():
            lines.append(f"{pad4}{k}: {_yaml_str(v)}")


def render_yaml(pseudo_svc: str, boto3_client: str, blocks: list[dict]) -> str:
    n_ops = len(blocks)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines: list[str] = [
        f"# Auto-generated: minimum discoveries for check rules + inventory identifiers",
        f"# Sources: {pseudo_svc} (backed by {boto3_client})",
        f"# {n_ops} ops (from checks)",
        f"# Generated: {ts}",
        "version: '1.0'",
        "provider: aws",
        f"service: {pseudo_svc}",
        "services:",
        f"  client: {boto3_client}",
        "  module: boto3.client",
        "discovery:",
    ]
    for block in blocks:
        _write_block(lines, block)
    lines.append("")
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def generate_one(pseudo_svc: str, dry_run: bool = False) -> str:
    catalog_dirname, boto3_client = PSEUDO_MAP[pseudo_svc]
    catalog_dir = AWS_ROOT / catalog_dirname

    print(f"\n[{pseudo_svc}] ← {catalog_dirname}  client={boto3_client}")

    # 1. Load step4/step3/step2 from real catalog
    op_to_fields, entity_to_field = load_step4(catalog_dir)
    op_consumes = load_step3_consumes(catalog_dir)
    op_registry = load_step2(catalog_dir)

    if not op_to_fields:
        print(f"  WARN: no step4 fields found in {catalog_dir}")

    # 2. Load check discoveries
    check_discs = load_check_discoveries(pseudo_svc)
    if not check_discs:
        print(f"  SKIP: no discoveries.yaml in check engine for {pseudo_svc}")
        return ""

    # 3. Build blocks — preserving order from check discoveries.yaml
    blocks: list[dict] = []
    for disc in check_discs:
        action = disc["calls"][0]["action"]
        disc_id = disc.get("discovery_id")  # use id from check YAML (may differ from action name)
        parent_action: Optional[str] = None
        calls_params: Optional[dict] = None

        if "for_each" in disc:
            parent_did = disc["for_each"]
            parent_action = parent_did.split(".")[-1]  # last segment = action name

        # Use params from check YAML if available (already validated)
        if disc["calls"][0].get("params"):
            calls_params = disc["calls"][0]["params"]

        pascal = to_pascal(action)
        n_fields = len(op_to_fields.get(pascal, []))
        in_step2 = pascal in op_registry
        print(f"  op: {action:45s}  pascal={pascal}  step4_fields={n_fields}"
              f"  step2={'yes' if in_step2 else 'no'}"
              f"{'  for_each=' + parent_action if parent_action else ''}")

        block = build_block(
            action=action,
            pseudo_svc=pseudo_svc,
            op_to_fields=op_to_fields,
            entity_to_field=entity_to_field,
            op_consumes=op_consumes,
            parent_action=parent_action,
            calls_params_from_yaml=calls_params,
            discovery_id=disc_id,
            op_registry=op_registry,
        )
        blocks.append(block)

    # 4. Render and write
    yaml_text = render_yaml(pseudo_svc, boto3_client, blocks)

    out_dir = AWS_ROOT / pseudo_svc
    out_path_min = out_dir / f"step6_{pseudo_svc}_discoveries_minimum.yaml"
    # Also write the canonical step6_{svc}.discovery.yaml that sync_discoveries_to_db.py expects
    out_path_disc = out_dir / f"step6_{pseudo_svc}.discovery.yaml"

    if dry_run:
        print(f"\n  [DRY-RUN] would write → {out_path_min.relative_to(BASE.parent.parent)}")
        print(textwrap.indent(yaml_text[:600] + ("..." if len(yaml_text) > 600 else ""), "    "))
        return yaml_text

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path_min.write_text(yaml_text, encoding="utf-8")
    out_path_disc.write_text(yaml_text, encoding="utf-8")
    print(f"  wrote → {out_path_min.relative_to(BASE.parent.parent)}")
    print(f"  wrote → {out_path_disc.relative_to(BASE.parent.parent)}")
    return yaml_text


def main() -> None:
    p = argparse.ArgumentParser(description="Generate step6 minimum YAMLs for pseudo-services")
    p.add_argument("--service", default=None, help="Generate for one service only")
    p.add_argument("--dry-run", action="store_true", help="Print output without writing")
    args = p.parse_args()

    targets = [args.service] if args.service else sorted(PSEUDO_MAP)
    for svc in targets:
        if svc not in PSEUDO_MAP:
            print(f"ERROR: unknown pseudo-service '{svc}'. Valid: {sorted(PSEUDO_MAP)}")
            continue
        generate_one(svc, dry_run=args.dry_run)

    print("\nDone.")


if __name__ == "__main__":
    main()
