#!/usr/bin/env python3
"""
Load service classification YAML files into the service_classification table.

This is the v2 loader that writes to the dedicated service_classification table
(migration 019) instead of resource_inventory_identifier. The key difference is
that resource_type uses the dotted format matching inventory_findings directly
(e.g., "ec2.instance" instead of separate service/resource_type columns).

Usage:
    python load_service_classifications_v2.py \
        --classifications-dir /path/to/service_classifications_v2 \
        --db-url postgresql://user:pass@host:5432/threat_engine_inventory

    # Or with env vars:
    INVENTORY_DB_HOST=localhost INVENTORY_DB_PORT=5432 \
    INVENTORY_DB_NAME=threat_engine_inventory INVENTORY_DB_USER=postgres \
    python load_service_classifications_v2.py

    # Dry run:
    python load_service_classifications_v2.py --dry-run

    # Single CSP:
    python load_service_classifications_v2.py --csp aws
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not found. Install: pip install psycopg2-binary")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

VALID_SCOPES = {"global", "regional", "vpc", "subnet", "az", "namespace", "cluster"}
VALID_CATEGORIES = {
    "compute", "container", "database", "storage", "network", "edge",
    "security", "identity", "encryption", "monitoring", "management",
    "messaging", "analytics", "ai_ml", "iot",
}
VALID_SERVICE_MODELS = {"IaaS", "PaaS", "FaaS", "SaaS"}
VALID_MANAGED_BY = {
    "aws", "azure", "gcp", "oci", "alicloud", "ibm", "customer", "shared",
}
VALID_ACCESS_PATTERNS = {"public", "private", "internal"}
VALID_ENCRYPTION_SCOPES = {"at_rest", "in_transit", "both", None}
VALID_CONTAINER_PARENTS = {
    None, "null", "org", "account", "region", "vpc", "subnet",
    "cluster", "namespace",
}

# Columns to UPSERT (excluding id, created_at)
UPSERT_COLUMNS = [
    "csp", "resource_type", "service", "resource_name", "display_name",
    "scope", "category", "subcategory", "service_model", "managed_by",
    "access_pattern", "is_container", "container_parent", "encryption_scope",
    "diagram_priority", "csp_category",
]


# ── Validation ────────────────────────────────────────────────────────────────

def validate_entry(entry: Dict[str, Any], csp: str, idx: int) -> List[str]:
    """Validate a single classification entry. Returns list of error messages."""
    errors = []
    rt = entry.get("resource_type", "?")
    label = f"{csp}[{idx}] {rt}"

    # Required fields
    if not entry.get("resource_type"):
        errors.append(f"{label}: missing required field 'resource_type'")
    if not entry.get("category"):
        errors.append(f"{label}: missing required field 'category'")

    # resource_type must be dotted format
    rt_val = entry.get("resource_type", "")
    if rt_val and "." not in rt_val:
        errors.append(f"{label}: resource_type must be dotted format (e.g., 'ec2.instance'), got '{rt_val}'")

    # Validate enums
    if entry.get("scope") and entry["scope"] not in VALID_SCOPES:
        errors.append(f"{label}: invalid scope '{entry['scope']}'")

    if entry.get("category") and entry["category"] not in VALID_CATEGORIES:
        errors.append(f"{label}: invalid category '{entry['category']}'")

    if entry.get("service_model") and entry["service_model"] not in VALID_SERVICE_MODELS:
        errors.append(f"{label}: invalid service_model '{entry['service_model']}'")

    if entry.get("managed_by") and entry["managed_by"] not in VALID_MANAGED_BY:
        errors.append(f"{label}: invalid managed_by '{entry['managed_by']}'")

    if entry.get("access_pattern") and entry["access_pattern"] not in VALID_ACCESS_PATTERNS:
        errors.append(f"{label}: invalid access_pattern '{entry['access_pattern']}'")

    enc = entry.get("encryption_scope")
    if enc and enc not in {"at_rest", "in_transit", "both"}:
        errors.append(f"{label}: invalid encryption_scope '{enc}'")

    prio = entry.get("diagram_priority")
    if prio is not None and (not isinstance(prio, int) or prio < 1 or prio > 5):
        errors.append(f"{label}: diagram_priority must be 1-5, got '{prio}'")

    return errors


# ── DB Connection ─────────────────────────────────────────────────────────────

def get_db_connection(db_url: Optional[str] = None):
    """Get a database connection from URL or env vars."""
    if db_url:
        return psycopg2.connect(db_url)

    host = os.environ.get("INVENTORY_DB_HOST", os.environ.get("DB_HOST", "localhost"))
    port = os.environ.get("INVENTORY_DB_PORT", os.environ.get("DB_PORT", "5432"))
    name = os.environ.get("INVENTORY_DB_NAME", os.environ.get("DB_NAME", "threat_engine_inventory"))
    user = os.environ.get("INVENTORY_DB_USER", os.environ.get("DB_USER", "postgres"))
    password = os.environ.get("INVENTORY_DB_PASSWORD", os.environ.get("DB_PASSWORD", ""))

    return psycopg2.connect(
        host=host, port=int(port), dbname=name,
        user=user, password=password,
    )


# ── Prepare entry ────────────────────────────────────────────────────────────

def prepare_entry(csp: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare a validated entry for DB insertion."""
    rt = entry["resource_type"]
    # Split dotted resource_type into service and resource_name
    parts = rt.split(".", 1)
    service = parts[0]
    resource_name = parts[1] if len(parts) > 1 else parts[0]

    # Normalize null container_parent
    cp = entry.get("container_parent")
    if cp == "null" or cp == "None":
        cp = None

    return {
        "csp": csp,
        "resource_type": rt,
        "service": service,
        "resource_name": resource_name,
        "display_name": entry.get("display_name"),
        "scope": entry.get("scope", "regional"),
        "category": entry["category"],
        "subcategory": entry.get("subcategory"),
        "service_model": entry.get("service_model", "PaaS"),
        "managed_by": entry.get("managed_by", "shared"),
        "access_pattern": entry.get("access_pattern", "private"),
        "is_container": entry.get("is_container", False),
        "container_parent": cp,
        "encryption_scope": entry.get("encryption_scope"),
        "diagram_priority": entry.get("diagram_priority", 3),
        "csp_category": entry.get("csp_category"),
    }


# ── Load & Apply ──────────────────────────────────────────────────────────────

def load_yaml(filepath: Path) -> Dict[str, Any]:
    """Load and return a classification YAML file."""
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def apply_classifications(
    classifications_dir: str,
    db_url: Optional[str] = None,
    dry_run: bool = False,
    csp_filter: Optional[str] = None,
) -> Dict[str, int]:
    """
    Load classification YAML(s) and upsert into service_classification.

    Returns:
        {"inserted": N, "updated": N, "errors": N, "validated": N}
    """
    stats = {"inserted": 0, "updated": 0, "errors": 0, "validated": 0}
    dir_path = Path(classifications_dir)

    if not dir_path.is_dir():
        logger.error("Classifications directory not found: %s", classifications_dir)
        return stats

    # Find YAML files
    yaml_files = sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml"))
    if csp_filter:
        yaml_files = [f for f in yaml_files if f.stem == csp_filter]

    if not yaml_files:
        logger.warning("No YAML files found in %s", classifications_dir)
        return stats

    logger.info("Found %d classification file(s): %s",
                len(yaml_files), [f.name for f in yaml_files])

    # Parse and validate all files first
    all_entries = []  # list of prepared entry dicts

    for filepath in yaml_files:
        logger.info("Loading %s ...", filepath.name)
        data = load_yaml(filepath)
        csp = data.get("csp", filepath.stem)
        entries = data.get("classifications", [])

        for idx, entry in enumerate(entries):
            errs = validate_entry(entry, csp, idx)
            if errs:
                for e in errs:
                    logger.error("VALIDATION: %s", e)
                stats["errors"] += 1
                continue
            stats["validated"] += 1
            all_entries.append(prepare_entry(csp, entry))

    logger.info("Validated %d entries (%d errors)", stats["validated"], stats["errors"])

    if dry_run:
        logger.info("DRY RUN — %d entries would be upserted:", len(all_entries))
        for e in all_entries[:10]:
            logger.info("  %s / %s → %s/%s (P%d)",
                        e["csp"], e["resource_type"], e["category"],
                        e["subcategory"], e["diagram_priority"])
        if len(all_entries) > 10:
            logger.info("  ... and %d more", len(all_entries) - 10)
        stats["inserted"] = len(all_entries)
        return stats

    # Build UPSERT SQL
    cols = ", ".join(UPSERT_COLUMNS)
    placeholders = ", ".join(["%s"] * len(UPSERT_COLUMNS))
    update_set = ", ".join(
        f"{col} = EXCLUDED.{col}"
        for col in UPSERT_COLUMNS
        if col not in ("csp", "resource_type")  # skip unique key columns
    )

    sql = f"""
        INSERT INTO service_classification ({cols})
        VALUES ({placeholders})
        ON CONFLICT (csp, resource_type)
        DO UPDATE SET {update_set}, updated_at = NOW()
    """

    # Apply to DB
    conn = get_db_connection(db_url)
    try:
        with conn.cursor() as cur:
            for entry in all_entries:
                values = [entry[col] for col in UPSERT_COLUMNS]
                try:
                    cur.execute(sql, values)
                    # rowcount=1 for both insert and update in ON CONFLICT
                    stats["inserted"] += 1
                except Exception as e:
                    logger.error("DB error for %s/%s: %s",
                                 entry["csp"], entry["resource_type"], e)
                    stats["errors"] += 1

            conn.commit()
            logger.info(
                "Done. upserted=%d, errors=%d",
                stats["inserted"], stats["errors"],
            )
    finally:
        conn.close()

    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Load service classifications into service_classification table"
    )
    parser.add_argument(
        "--classifications-dir",
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "service_classifications",
        ),
        help="Directory containing {csp}.yaml classification files",
    )
    parser.add_argument("--db-url", default=None, help="PostgreSQL connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Print without executing")
    parser.add_argument("--csp", default=None, help="Filter to single CSP (e.g., aws)")

    args = parser.parse_args()

    stats = apply_classifications(
        classifications_dir=args.classifications_dir,
        db_url=args.db_url,
        dry_run=args.dry_run,
        csp_filter=args.csp,
    )

    # Exit code: 0 if no errors, 1 if any errors
    sys.exit(0 if stats["errors"] == 0 else 1)


if __name__ == "__main__":
    main()
