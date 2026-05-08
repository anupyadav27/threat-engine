#!/usr/bin/env python3
"""
Enrich discovery YAMLs with inventory identifier annotations and missing ops.

For each enabled resource_inventory_identifier row in the DB:
  1. For each op in root_ops:
     - Look up in azure/gcp master_read_ops CSV to get produced_fields,
       resource_id_field, chain_ops, is_independent
     - Find (or create) the discovery YAML
     - If op NOT already in YAML: append a new discovery entry
     - The identifier field in the emit section gets annotated:
         # _inventory_identifier_ — {identifier_pattern}

Two output modes:
  discovery_generator (default):
    catalog/discovery_generator/{csp}/{sdk_service}/step6_{sdk_service}.discovery.yaml

  check_rule:
    catalog/rule/{csp}_rule_check/{service}/step6_{service}.discovery.yaml
    (only writes if the check rule service directory already exists)

Usage:
    # Dry run:
    python enrich_discovery_with_inventory_ops.py --dry-run

    # Write into check rule dirs (recommended):
    python enrich_discovery_with_inventory_ops.py --output-mode check_rule --csp azure gcp

    # Write into discovery_generator dirs:
    python enrich_discovery_with_inventory_ops.py --output-mode discovery_generator --csp azure gcp
"""

import argparse
import csv
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not found. Install: pip install psycopg2-binary")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

csv.field_size_limit(10 * 1024 * 1024)

# ── Repo root ─────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CATALOG_DISCOVERY = REPO_ROOT / "catalog" / "discovery_generator"
DEFAULT_CATALOG_RULE = REPO_ROOT / "catalog" / "rule"

# ── Master CSV paths ──────────────────────────────────────────────────────────
MASTER_CSV: Dict[str, Path] = {
    "azure": DEFAULT_CATALOG_DISCOVERY / "azure" / "azure_master_read_ops.csv",
    "gcp": DEFAULT_CATALOG_DISCOVERY / "gcp" / "gcp_master_read_ops.csv",
}

# ── Check rule directory suffix per CSP ───────────────────────────────────────
CHECK_RULE_DIR_SUFFIX: Dict[str, str] = {
    "azure": "azure_rule_check",
    "gcp": "gcp_rule_check",
    "aws": "aws_rule_check",
    "k8s": "k8s_rule_check",
}

# ── Field priorities for emit section (most important first) ─────────────────
AZURE_PRIORITY_FIELDS = [
    "id", "name", "type", "location", "tags", "resource_uid",
    "sku", "identity", "kind", "provisioning_state", "power_state",
    "properties", "etag", "zones", "system_data",
]
GCP_PRIORITY_FIELDS = [
    "name", "createTime", "updateTime", "labels", "state", "status",
    "displayName", "description", "uid", "etag", "annotations",
]

MAX_EMIT_FIELDS = 20  # cap to keep YAML readable


# ─────────────────────────────────────────────────────────────────────────────
# Master CSV helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_master_csv(csp: str, catalog_root: Path) -> Dict[str, dict]:
    """Load master read ops CSV into a dict keyed by producing_op."""
    csv_path = catalog_root / csp / f"{csp}_master_read_ops.csv"
    if not csv_path.exists():
        logger.warning("Master CSV not found: %s", csv_path)
        return {}

    ops: Dict[str, dict] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ops[row["producing_op"]] = row
    logger.info("Loaded %d ops from %s master CSV", len(ops), csp)
    return ops


# ─────────────────────────────────────────────────────────────────────────────
# YAML generation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sdk_service_from_op(op: str) -> str:
    """Return the SDK service name: 2nd segment of 'csp.service.resource.method'."""
    parts = op.split(".")
    return parts[1] if len(parts) >= 2 else ""


def _action_from_op(op: str) -> str:
    """Return the action string: everything after 'csp.service.'."""
    parts = op.split(".")
    return ".".join(parts[2:]) if len(parts) > 2 else op


def _gcp_python_call(action: str) -> str:
    """Build GCP python call comment from action string.

    e.g.  projects.instances.appProfiles.list
       -> svc.projects().instances().appProfiles().list(**params).execute()
    """
    parts = action.split(".")
    if not parts:
        return f"svc.{action}(**params).execute()"
    method = parts[-1]
    chain = "".join(f"{p}()." for p in parts[:-1])
    return f"svc.{chain}{method}(**params).execute()"


def _parse_azure_fields(produced_fields: str) -> List[str]:
    """Parse Azure produced_fields 'value[].id|value[].name|...' → ['id','name',...]."""
    if not produced_fields:
        return []
    fields = []
    for f in produced_fields.split("|"):
        f = f.strip()
        if not f:
            continue
        # strip 'value[].', 'value[].' variants
        if "[]." in f:
            f = f.split("[].")[-1]
        fields.append(f)
    return fields


def _parse_gcp_fields(produced_fields: str) -> Tuple[str, List[str]]:
    """Parse GCP produced_fields → (list_key, [field_names]).

    e.g. 'instances[].name|instances[].createTime' → ('instances', ['name','createTime'])
    If no list key found, returns ('items', fields).
    """
    if not produced_fields:
        return "items", []

    all_fields = []
    list_key = "items"
    for f in produced_fields.split("|"):
        f = f.strip()
        if not f:
            continue
        if "[" in f and "]." in f:
            bracket = f.index("[")
            bracket_end = f.index("].")
            list_key = f[:bracket]
            field_name = f[bracket_end + 2:]
        else:
            field_name = f
        all_fields.append(field_name)
    return list_key, all_fields


def _prioritize_fields(fields: List[str], priority: List[str], max_count: int) -> List[str]:
    """Return fields ordered by priority list, capped at max_count."""
    seen: Set[str] = set()
    result = []
    # Add priority fields first (if present in fields)
    field_set = set(fields)
    for pf in priority:
        if pf in field_set and pf not in seen:
            result.append(pf)
            seen.add(pf)
    # Add remaining fields
    for f in fields:
        if f not in seen:
            result.append(f)
            seen.add(f)
    return result[:max_count]


def _get_parent_op(chain_ops: str, current_op: str) -> Optional[str]:
    """Extract parent op from chain string 'op1 -> op2 -> current_op'."""
    if not chain_ops or "->" not in chain_ops:
        return None
    parts = [p.strip() for p in chain_ops.split("->")]
    # Find current_op in parts and return the one before it
    for i, p in enumerate(parts):
        if p == current_op and i > 0:
            return parts[i - 1]
    # Fallback: return second-to-last
    if len(parts) >= 2:
        return parts[-2]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Azure YAML entry builder
# ─────────────────────────────────────────────────────────────────────────────

def build_azure_entry(op: str, master_row: Optional[dict], identifier_pattern: str) -> str:
    """Build an Azure discovery entry YAML string."""
    action = _action_from_op(op)

    # Determine if independent and get parent for for_each
    is_independent = True
    parent_op = None
    if master_row:
        is_independent = master_row.get("is_independent", "Yes") == "Yes"
        if not is_independent:
            parent_op = _get_parent_op(master_row.get("chain_ops", ""), op)

    # Parse produced fields
    produced_fields = master_row.get("produced_fields", "") if master_row else ""
    raw_fields = _parse_azure_fields(produced_fields)
    id_field_raw = master_row.get("resource_id_field", "") if master_row else ""
    id_field = id_field_raw.replace("value[].", "").strip() if id_field_raw else None

    # Prioritize fields
    if raw_fields:
        emit_fields = _prioritize_fields(raw_fields, AZURE_PRIORITY_FIELDS, MAX_EMIT_FIELDS)
    else:
        # Fallback minimal fields
        emit_fields = ["id", "name", "type", "location", "tags"]
        if id_field and id_field not in emit_fields:
            emit_fields.insert(0, id_field)

    # Determine if this is a list or get op
    op_kind = master_row.get("op_kind", "read_list") if master_row else "read_list"
    is_list_op = op_kind == "read_list" or "list" in action.split(".")[-1].lower()

    lines = []

    # Discovery entry header
    lines.append(f"- discovery_id: {op}")
    if not is_independent and parent_op:
        lines.append(f"  for_each: {parent_op}")
    lines.append(f"  calls:")
    lines.append(f"  - action: {action}")
    lines.append(f"    save_as: response")
    lines.append(f"    on_error: continue")

    # Params for dependent ops
    if not is_independent and parent_op:
        lines.append(f"    params:")
        lines.append(f"      resource_name: '{{{{ item.name }}}}'")

    # Emit section
    lines.append(f"  emit:")
    lines.append(f"    as: item")
    if is_list_op:
        lines.append(f"    items_for: '{{{{ response.value }}}}'")
    lines.append(f"    item:")

    # Emit fields with identifier annotation
    for field in emit_fields:
        if is_list_op:
            value = f"'{{{{ item.{field} }}}}'"
        else:
            value = f"'{{{{ response.{field} }}}}'"

        if id_field and field == id_field:
            annotation = f"  # _inventory_identifier_ — {identifier_pattern}"
        else:
            annotation = ""
        lines.append(f"      {field}: {value}{annotation}")

    # If id_field not in emit_fields, append it
    if id_field and id_field not in emit_fields:
        value = f"'{{{{ item.{id_field} }}}}'" if is_list_op else f"'{{{{ response.{id_field} }}}}'"
        annotation = f"  # _inventory_identifier_ — {identifier_pattern}"
        lines.append(f"      {id_field}: {value}{annotation}")
    elif not id_field:
        # No identifier field found in CSV — add a comment
        lines.append(f"      # _inventory_identifier_ — {identifier_pattern}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# GCP YAML entry builder
# ─────────────────────────────────────────────────────────────────────────────

def build_gcp_entry(op: str, master_row: Optional[dict], identifier_pattern: str) -> str:
    """Build a GCP discovery entry YAML string (2-space indented list item)."""
    action = _action_from_op(op)
    python_call = _gcp_python_call(action)

    is_independent = True
    parent_op = None
    if master_row:
        is_independent = master_row.get("is_independent", "Yes") == "Yes"
        if not is_independent:
            parent_op = _get_parent_op(master_row.get("chain_ops", ""), op)

    produced_fields = master_row.get("produced_fields", "") if master_row else ""
    id_field_raw = master_row.get("resource_id_field", "") if master_row else ""

    list_key, raw_fields = _parse_gcp_fields(produced_fields)
    # Strip list_key prefix from id_field
    if id_field_raw:
        if "[]." in id_field_raw:
            id_field = id_field_raw.split("[].")[-1]
        else:
            id_field = id_field_raw
    else:
        id_field = None

    if raw_fields:
        emit_fields = _prioritize_fields(raw_fields, GCP_PRIORITY_FIELDS, MAX_EMIT_FIELDS)
    else:
        emit_fields = ["name", "createTime", "labels", "state"]
        if id_field and id_field not in emit_fields:
            emit_fields.insert(0, id_field)

    is_list_op = master_row.get("op_kind", "read_list") == "read_list" if master_row else True

    lines = []
    lines.append(f"  - discovery_id: {op}")
    lines.append(f"    # python: {python_call}")
    if not is_independent and parent_op:
        lines.append(f"    for_each: {parent_op}")
    lines.append(f"    calls:")
    lines.append(f"      - action: {action}")
    lines.append(f"        params: {{}}")
    lines.append(f"        save_as: response")
    lines.append(f"        on_error: continue")
    lines.append(f"    emit:")
    lines.append(f"      as: item")
    if is_list_op and list_key:
        lines.append(f"      items_for: '{{{{ response.{list_key} }}}}'")
    lines.append(f"      item:")

    for field in emit_fields:
        value = f"'{{{{ item.{field} }}}}'"
        if id_field and field == id_field:
            annotation = f"  # _inventory_identifier_ — {identifier_pattern}"
        else:
            annotation = ""
        lines.append(f"        {field}: {value}{annotation}")

    if id_field and id_field not in emit_fields:
        annotation = f"  # _inventory_identifier_ — {identifier_pattern}"
        lines.append(f"        {id_field}: '{{{{ item.{id_field} }}}}'{annotation}")
    elif not id_field:
        lines.append(f"        # _inventory_identifier_ — {identifier_pattern}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# YAML file operations
# ─────────────────────────────────────────────────────────────────────────────

def op_in_yaml(content: str, discovery_id: str) -> bool:
    """Return True if discovery_id already present in YAML content."""
    return f"discovery_id: {discovery_id}" in content


def build_azure_yaml_header(sdk_service: str) -> str:
    """Build header for a new Azure discovery YAML."""
    return (
        f"version: '1.0'\n"
        f"provider: azure\n"
        f"service: {sdk_service}\n"
        f"services:\n"
        f"  client: {sdk_service}\n"
        f"  module: azure.mgmt.{sdk_service}\n"
        f"discovery:\n"
    )


def build_gcp_yaml_header(sdk_service: str) -> str:
    """Build header for a new GCP discovery YAML."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"# ============================================================\n"
        f"# Discovery YAML — {sdk_service}\n"
        f"# Generated: {now}\n"
        f"# ============================================================\n"
        f"version: '1.0'\n"
        f"provider: gcp\n"
        f"service: {sdk_service}\n"
        f"\n"
        f"services:\n"
        f"  client: {sdk_service}\n"
        f"  module: \"googleapiclient.discovery.build('{sdk_service}', 'v1')\"\n"
        f"\n"
        f"anchors:\n"
        f"  project_id: null\n"
        f"  org_id: null\n"
        f"  folder_id: null\n"
        f"  location: null\n"
        f"  zone: null\n"
        f"  region: null\n"
        f"\n"
        f"checks: []\n"
        f"\n"
        f"discovery:\n"
        f"\n"
    )


def append_entry_to_yaml(yaml_path: Path, entry: str, csp: str, dry_run: bool) -> bool:
    """Append a discovery entry to an existing YAML file. Returns True if changed."""
    with open(yaml_path, encoding="utf-8") as f:
        content = f.read()

    # Ensure there's a newline before appending
    separator = "\n" if content.endswith("\n") else "\n\n"
    new_content = content + separator + entry + "\n"

    if not dry_run:
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(new_content)
    return True


def create_yaml_with_entries(yaml_path: Path, sdk_service: str, csp: str,
                             entries: List[str], dry_run: bool) -> None:
    """Create a new discovery YAML file with the given entries."""
    if csp == "azure":
        header = build_azure_yaml_header(sdk_service)
        body = "\n".join(entries)
    else:
        header = build_gcp_yaml_header(sdk_service)
        body = "\n".join(entries)

    content = header + body + "\n"

    if not dry_run:
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(content)
    logger.info("  [CREATE] %s", yaml_path)


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_db_url(args: argparse.Namespace) -> str:
    """Build PostgreSQL connection URL from args or env vars."""
    if args.db_url:
        return args.db_url
    host = os.getenv("INVENTORY_DB_HOST", "localhost")
    port = os.getenv("INVENTORY_DB_PORT", "5432")
    db = os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
    user = os.getenv("INVENTORY_DB_USER", "inventory_user")
    pw = os.getenv("INVENTORY_DB_PASSWORD", "inventory_password")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


def fetch_enabled_rows(conn, csps: List[str]) -> List[dict]:
    """Fetch enabled resource_inventory_identifier rows for the given CSPs."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT csp, service, resource_type, root_ops, identifier_pattern, identifier_type
          FROM resource_inventory_identifier
         WHERE should_inventory = TRUE
           AND csp = ANY(%s)
           AND root_ops IS NOT NULL
           AND jsonb_array_length(root_ops) > 0
        ORDER BY csp, service, resource_type
        """,
        (csps,),
    )
    rows = cur.fetchall()
    cur.close()
    logger.info("Fetched %d enabled rows from DB", len(rows))
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Main processing
# ─────────────────────────────────────────────────────────────────────────────

def resolve_yaml_path(
    csp: str,
    row: dict,
    op: str,
    output_mode: str,
    catalog_root: Path,
    rule_catalog_root: Path,
) -> Optional[Tuple[Path, str]]:
    """Return (yaml_path, file_service_name) or None if path not applicable.

    check_rule mode: writes to catalog/rule/{csp}_rule_check/{service}/step6_{service}.discovery.yaml
                     only if that service directory exists.
    discovery_generator mode: writes to catalog/discovery_generator/{csp}/{sdk_service}/step6_{sdk_service}.discovery.yaml
    """
    if output_mode == "check_rule":
        row_service = row["service"]
        dir_suffix = CHECK_RULE_DIR_SUFFIX.get(csp)
        if not dir_suffix:
            return None
        svc_dir = rule_catalog_root / dir_suffix / row_service
        if not svc_dir.is_dir():
            logger.debug("  [SKIP] no check rule dir for %s/%s", csp, row_service)
            return None
        yaml_path = svc_dir / f"step6_{row_service}.discovery.yaml"
        return yaml_path, row_service
    else:
        sdk_service = _sdk_service_from_op(op)
        if not sdk_service:
            return None
        yaml_path = catalog_root / csp / sdk_service / f"step6_{sdk_service}.discovery.yaml"
        return yaml_path, sdk_service


def process_csp(
    csp: str,
    rows: List[dict],
    master_ops: Dict[str, dict],
    catalog_root: Path,
    rule_catalog_root: Path,
    output_mode: str,
    dry_run: bool,
) -> Dict[str, int]:
    """Process all enabled rows for one CSP. Returns stats."""
    import json as _json

    stats = {
        "ops_skipped_exists": 0,
        "ops_appended": 0,
        "ops_created_new_yaml": 0,
        "ops_not_in_csv": 0,
        "ops_no_check_dir": 0,
        "yamls_created": 0,
        "yamls_updated": 0,
    }

    # Group new entries by yaml_path for batch-create
    # yaml_path → [(op, entry_string)]
    yaml_new_entries: Dict[Path, List[Tuple[str, str]]] = {}
    yaml_path_to_service: Dict[Path, str] = {}

    for row in rows:
        if row["csp"] != csp:
            continue

        root_ops_raw = row["root_ops"]
        if isinstance(root_ops_raw, list):
            root_ops_list = root_ops_raw
        elif isinstance(root_ops_raw, str):
            try:
                root_ops_list = _json.loads(root_ops_raw)
            except Exception:
                root_ops_list = []
        else:
            root_ops_list = []

        identifier_pattern = row.get("identifier_pattern") or ""

        for op_entry in root_ops_list:
            if isinstance(op_entry, dict):
                op = (
                    op_entry.get("operation")
                    or op_entry.get("op")
                    or op_entry.get("discovery_id")
                    or ""
                )
            else:
                op = str(op_entry)
            if not op:
                continue

            # Resolve output YAML path
            result = resolve_yaml_path(
                csp, row, op, output_mode, catalog_root, rule_catalog_root
            )
            if result is None:
                stats["ops_no_check_dir"] += 1
                continue

            yaml_path, file_service = result
            yaml_path_to_service[yaml_path] = file_service

            # Look up in master CSV
            master_row = master_ops.get(op)
            if not master_row:
                stats["ops_not_in_csv"] += 1
                logger.debug("Op not in master CSV: %s — generating minimal entry", op)

            # Build the discovery entry
            if csp == "azure":
                entry = build_azure_entry(op, master_row, identifier_pattern)
            else:
                entry = build_gcp_entry(op, master_row, identifier_pattern)

            # Check if YAML exists
            if yaml_path.exists():
                with open(yaml_path, encoding="utf-8") as f:
                    content = f.read()
                if op_in_yaml(content, op):
                    stats["ops_skipped_exists"] += 1
                    logger.debug("  [SKIP]   %s already in %s", op, yaml_path.name)
                    continue
                logger.info("  [APPEND] %s → %s", op, yaml_path.name)
                if append_entry_to_yaml(yaml_path, entry, csp, dry_run):
                    stats["ops_appended"] += 1
                    stats["yamls_updated"] += 1
            else:
                if yaml_path not in yaml_new_entries:
                    yaml_new_entries[yaml_path] = []
                yaml_new_entries[yaml_path].append((op, entry))
                stats["ops_created_new_yaml"] += 1

    # Create new YAML files (batch per yaml_path)
    for yaml_path, op_entry_list in yaml_new_entries.items():
        file_service = yaml_path_to_service[yaml_path]
        logger.info("  [CREATE] %s (%d ops)", yaml_path.name, len(op_entry_list))
        entries = [entry for _, entry in op_entry_list]
        create_yaml_with_entries(yaml_path, file_service, csp, entries, dry_run)
        stats["yamls_created"] += 1

    return stats


def print_summary(all_stats: Dict[str, Dict[str, int]], dry_run: bool, output_mode: str) -> None:
    prefix = "[DRY RUN] " if dry_run else ""
    print(f"\n{'=' * 72}")
    print(f"{prefix}ENRICH DISCOVERY YAML SUMMARY  (mode: {output_mode})")
    print("=" * 72)
    for csp, s in all_stats.items():
        print(f"\nCSP: {csp.upper()}")
        print(f"  Ops already in YAML (skipped):   {s['ops_skipped_exists']:>6}")
        print(f"  Ops appended to existing YAMLs:  {s['ops_appended']:>6}")
        print(f"  Ops added to new YAMLs:          {s['ops_created_new_yaml']:>6}")
        print(f"  Ops not in master CSV:           {s['ops_not_in_csv']:>6}")
        print(f"  Ops skipped (no check dir):      {s['ops_no_check_dir']:>6}")
        print(f"  YAMLs updated:                   {s['yamls_updated']:>6}")
        print(f"  YAMLs created:                   {s['yamls_created']:>6}")
    print("=" * 72)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich discovery YAMLs with inventory identifier ops"
    )
    parser.add_argument(
        "--catalog-root",
        default=str(DEFAULT_CATALOG_DISCOVERY),
        help=f"Path to catalog/discovery_generator (default: {DEFAULT_CATALOG_DISCOVERY})",
    )
    parser.add_argument(
        "--rule-catalog-root",
        default=str(DEFAULT_CATALOG_RULE),
        help=f"Path to catalog/rule (default: {DEFAULT_CATALOG_RULE})",
    )
    parser.add_argument(
        "--output-mode",
        default="check_rule",
        choices=["check_rule", "discovery_generator"],
        help=(
            "check_rule: write to catalog/rule/{csp}_rule_check/{service}/ (default); "
            "discovery_generator: write to catalog/discovery_generator/{csp}/{sdk_service}/"
        ),
    )
    parser.add_argument(
        "--db-url", default=None, help="PostgreSQL connection URL (overrides env vars)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without writing files"
    )
    parser.add_argument(
        "--csp",
        nargs="+",
        default=["azure", "gcp"],
        choices=["azure", "gcp"],
        help="CSPs to process (default: azure gcp)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show DEBUG logs"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.dry_run:
        logger.info("DRY RUN — no files will be written")

    catalog_root = Path(args.catalog_root)
    rule_catalog_root = Path(args.rule_catalog_root)

    if not catalog_root.is_dir():
        logger.error("Catalog discovery root not found: %s", catalog_root)
        sys.exit(1)
    if args.output_mode == "check_rule" and not rule_catalog_root.is_dir():
        logger.error("Rule catalog root not found: %s", rule_catalog_root)
        sys.exit(1)

    logger.info("Output mode: %s", args.output_mode)

    # Load master CSVs
    master_ops_by_csp: Dict[str, Dict[str, dict]] = {}
    for csp in args.csp:
        master_ops_by_csp[csp] = load_master_csv(csp, catalog_root)

    # Connect to DB
    db_url = build_db_url(args)
    logger.info("Connecting to DB: %s", db_url.split("@")[-1])
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
    except Exception as exc:
        logger.error("DB connection failed: %s", exc)
        sys.exit(1)

    # Fetch enabled rows
    rows = fetch_enabled_rows(conn, args.csp)
    conn.close()

    if not rows:
        logger.info("No enabled rows found — nothing to do")
        return

    # Process each CSP
    all_stats: Dict[str, Dict[str, int]] = {}
    for csp in args.csp:
        logger.info("Processing CSP: %s", csp.upper())
        csp_rows = [r for r in rows if r["csp"] == csp]
        logger.info("  %d enabled rows", len(csp_rows))
        stats = process_csp(
            csp=csp,
            rows=csp_rows,
            master_ops=master_ops_by_csp[csp],
            catalog_root=catalog_root,
            rule_catalog_root=rule_catalog_root,
            output_mode=args.output_mode,
            dry_run=args.dry_run,
        )
        all_stats[csp] = stats

    print_summary(all_stats, args.dry_run, args.output_mode)


if __name__ == "__main__":
    main()
