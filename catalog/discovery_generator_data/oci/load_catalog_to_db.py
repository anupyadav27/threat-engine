#!/usr/bin/env python3
"""
Load oci_field_rule_catalog.csv into the database.

Populates 4 existing/new tables:
  1. csp_field_catalog   (NEW)  — field rows (discovery chain, operators, identifiers)
  2. rule_metadata       (existing) — rule_id, severity, title, frameworks
  3. rule_checks         (existing) — rule_id, check_config (for_each + var + conditions)
  4. rule_discoveries    (existing) — service, discoveries_data JSONB (from step6 YAMLs)

The CSV is the single source of truth. This script is idempotent (upsert on conflict).

Usage:
  python3 load_catalog_to_db.py [--csv PATH] [--dsn DSN] [--dry-run]
  python3 load_catalog_to_db.py --service object_storage  # single service
"""

from __future__ import annotations
import argparse, csv, json, os, sys, yaml
from collections import defaultdict
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE        = Path("/Users/apple/Desktop/threat-engine")
CATALOG_CSV = BASE / "catalog/discovery_generator/oci/oci_field_rule_catalog.csv"
STEP6_DIR   = BASE / "catalog/discovery_generator/oci"
DEFAULT_DSN = os.getenv(
    "CHECK_DB_DSN",
    "postgresql://postgres:postgres@localhost:5432/check_db"
)

# ── Row readers ───────────────────────────────────────────────────────────────

def load_catalog(csv_path: Path, service_filter: str | None = None):
    field_rows, rule_rows = [], []
    for r in csv.DictReader(open(csv_path)):
        if service_filter and r["service"] != service_filter:
            continue
        if r.get("check_rule_id"):
            rule_rows.append(r)
        else:
            field_rows.append(r)
    return field_rows, rule_rows


def load_step6_yaml(service: str) -> dict | None:
    """Load the step6 discovery YAML for a service as a dict."""
    p = STEP6_DIR / service / f"step6_{service}.discovery.yaml"
    if not p.exists():
        return None
    return yaml.safe_load(p.read_text())


# ── SQL builders ──────────────────────────────────────────────────────────────

FIELD_CATALOG_UPSERT = """
INSERT INTO csp_field_catalog (
    csp, service, field_path, item_var_path, field_type, is_id,
    resource_type, resource_id_field, resource_id_param,
    producing_op, op_kind, is_independent,
    root_op, chain_ops, chain_length, hop_distance,
    python_call, http_path,
    operators, operators_no_value
)
VALUES (
    %(csp)s, %(service)s, %(field_path)s, %(item_var_path)s,
    %(field_type)s, %(is_id)s,
    %(resource_type)s, %(resource_id_field)s, %(resource_id_param)s,
    %(producing_op)s, %(op_kind)s, %(is_independent)s,
    %(root_op)s, %(chain_ops)s, %(chain_length)s, %(hop_distance)s,
    %(python_call)s, %(http_path)s,
    %(operators)s, %(operators_no_value)s
)
ON CONFLICT (csp, service, field_path)
DO UPDATE SET
    item_var_path      = EXCLUDED.item_var_path,
    field_type         = EXCLUDED.field_type,
    resource_type      = EXCLUDED.resource_type,
    resource_id_field  = EXCLUDED.resource_id_field,
    resource_id_param  = EXCLUDED.resource_id_param,
    producing_op       = EXCLUDED.producing_op,
    op_kind            = EXCLUDED.op_kind,
    is_independent     = EXCLUDED.is_independent,
    root_op            = EXCLUDED.root_op,
    chain_ops          = EXCLUDED.chain_ops,
    chain_length       = EXCLUDED.chain_length,
    hop_distance       = EXCLUDED.hop_distance,
    python_call        = EXCLUDED.python_call,
    operators          = EXCLUDED.operators,
    operators_no_value = EXCLUDED.operators_no_value,
    updated_at         = NOW()
"""

RULE_METADATA_UPSERT = """
INSERT INTO rule_metadata (
    rule_id, service, provider, resource,
    severity, title, description,
    source, generated_by, metadata_source
)
VALUES (
    %(rule_id)s, %(service)s, %(provider)s, %(resource)s,
    %(severity)s, %(title)s, %(description)s,
    'catalog', 'csp_field_catalog', 'catalog'
)
ON CONFLICT (rule_id, customer_id, tenant_id)
DO UPDATE SET
    severity     = EXCLUDED.severity,
    title        = EXCLUDED.title,
    description  = EXCLUDED.description,
    updated_at   = NOW()
"""

RULE_CHECKS_UPSERT = """
INSERT INTO rule_checks (
    rule_id, service, provider, check_type,
    check_config, source, generated_by, is_active
)
VALUES (
    %(rule_id)s, %(service)s, %(provider)s, 'default',
    %(check_config)s::jsonb, 'catalog', 'csp_field_catalog', TRUE
)
ON CONFLICT (rule_id, customer_id, tenant_id)
DO UPDATE SET
    check_config = EXCLUDED.check_config,
    is_active    = EXCLUDED.is_active,
    updated_at   = NOW()
"""

RULE_DISCOVERIES_UPSERT = """
INSERT INTO rule_discoveries (
    service, provider, version, discoveries_data,
    source, generated_by, is_active
)
VALUES (
    %(service)s, %(provider)s, '1.0', %(discoveries_data)s::jsonb,
    'catalog', 'csp_field_catalog', TRUE
)
ON CONFLICT (service, provider, customer_id, tenant_id)
DO UPDATE SET
    discoveries_data = EXCLUDED.discoveries_data,
    updated_at       = NOW()
"""

# ── Row converters ─────────────────────────────────────────────────────────────

def field_row_to_params(r: dict) -> dict:
    return {
        "csp":               r.get("csp", "oci"),
        "service":           r["service"],
        "field_path":        r["field_path"],
        "item_var_path":     r["item_var_path"],
        "field_type":        r.get("field_type", "string") or "string",
        "is_id":             r.get("is_id", "No") == "Yes",
        "resource_type":     r.get("resource_type", "") or None,
        "resource_id_field": r.get("resource_id_field", "ocid") or "ocid",
        "resource_id_param": r.get("resource_id_param", "") or None,
        "producing_op":      r.get("producing_op", "") or None,
        "op_kind":           r.get("op_kind", "") or None,
        "is_independent":    r.get("is_independent", "Yes") == "Yes",
        "root_op":           r.get("root_op", "") or None,
        "chain_ops":         r.get("chain_ops", "") or None,
        "chain_length":      int(r.get("chain_length", 1) or 1),
        "hop_distance":      int(r.get("hop_distance", 0) or 0),
        "python_call":       r.get("python_call", "") or None,
        "http_path":         r.get("http_path", "") or None,
        "operators":         r.get("operators", "") or None,
        "operators_no_value": r.get("operators_no_value", "") or None,
    }


def rule_title_from_id(rule_id: str) -> str:
    """oci.service.resource.some_check_name → 'Some Check Name'"""
    parts = rule_id.split(".")
    name = parts[-1] if parts else rule_id
    return name.replace("_", " ").title()


def rule_row_to_params(r: dict) -> tuple[dict, dict, dict]:
    """Returns (metadata_params, rule_checks_params, check_config)."""
    rule_id  = r["check_rule_id"]
    service  = r["service"]
    parts    = rule_id.split(".")
    resource = parts[2] if len(parts) > 2 else ""

    # check_config stored in rule_checks.check_config JSONB
    check_config = {
        "for_each":   r.get("check_for_each", ""),
        "var":        r.get("check_var", ""),
        "op":         r.get("check_condition_op", "exists"),
        "value":      r.get("check_condition_value", "") or None,
        "field_path": r.get("field_path", ""),
        "field_type": r.get("field_type", "string"),
    }
    # Include multi-condition JSON if present
    cond_json = r.get("check_conditions_json", "")
    if cond_json:
        check_config["conditions"] = json.loads(cond_json)

    meta_params = {
        "rule_id":     rule_id,
        "service":     service,
        "provider":    r.get("csp", "oci"),
        "resource":    resource,
        "severity":    r.get("check_severity", "MEDIUM").upper(),
        "title":       rule_title_from_id(rule_id),
        "description": r.get("check_description", "") or "",
    }
    check_params = {
        "rule_id":      rule_id,
        "service":      service,
        "provider":     r.get("csp", "oci"),
        "check_config": json.dumps(check_config),
    }
    return meta_params, check_params, check_config


# ── Load step6 YAML for rule_discoveries ──────────────────────────────────────

def discovery_params_for_service(service: str, csp: str = "oci") -> dict | None:
    disc_yaml = load_step6_yaml(service)
    if not disc_yaml:
        return None
    return {
        "service":          service,
        "provider":         csp,
        "discoveries_data": json.dumps(disc_yaml.get("discovery", [])),
    }


# ── Dry-run mode (print what would be inserted) ───────────────────────────────

def dry_run_report(field_rows, rule_rows, services):
    print("=== DRY RUN ===")
    print(f"csp_field_catalog rows  : {len(field_rows)}")
    print(f"rule_metadata rows      : {len(rule_rows)}")
    print(f"rule_checks rows        : {len(rule_rows)}")
    print(f"rule_discoveries rows   : {len(services)}")
    print()
    print("Sample field row → csp_field_catalog:")
    if field_rows:
        p = field_row_to_params(field_rows[0])
        for k, v in p.items():
            print(f"  {k:<22} {str(v)[:60]}")
    print()
    print("Sample rule row → rule_checks.check_config:")
    if rule_rows:
        _, rp, cfg = rule_row_to_params(rule_rows[0])
        print(f"  rule_id     : {rp['rule_id']}")
        print(f"  check_config: {json.dumps(cfg, indent=4)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv",      default=str(CATALOG_CSV))
    ap.add_argument("--dsn",      default=DEFAULT_DSN)
    ap.add_argument("--service",  default=None, help="Load single service only")
    ap.add_argument("--dry-run",  action="store_true")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: CSV not found: {csv_path}")
        sys.exit(1)

    print(f"Loading {csv_path.name} ...")
    field_rows, rule_rows = load_catalog(csv_path, args.service)
    services = sorted({r["service"] for r in field_rows})
    print(f"  {len(field_rows)} field rows  |  {len(rule_rows)} rule rows  |  {len(services)} services")

    if args.dry_run:
        dry_run_report(field_rows, rule_rows, services)
        return

    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
        sys.exit(1)

    conn = psycopg2.connect(args.dsn)
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # 1. csp_field_catalog
        print("\n[1/4] Loading csp_field_catalog ...")
        count = 0
        for r in field_rows:
            cur.execute(FIELD_CATALOG_UPSERT, field_row_to_params(r))
            count += 1
        print(f"  upserted {count} field rows")

        # 2. rule_metadata
        print("[2/4] Loading rule_metadata ...")
        count = 0
        for r in rule_rows:
            meta_p, _, _ = rule_row_to_params(r)
            cur.execute(RULE_METADATA_UPSERT, meta_p)
            count += 1
        print(f"  upserted {count} rule_metadata rows")

        # 3. rule_checks
        print("[3/4] Loading rule_checks ...")
        count = 0
        for r in rule_rows:
            _, check_p, _ = rule_row_to_params(r)
            cur.execute(RULE_CHECKS_UPSERT, check_p)
            count += 1
        print(f"  upserted {count} rule_checks rows")

        # 4. rule_discoveries (one row per service, from step6 YAML)
        print("[4/4] Loading rule_discoveries ...")
        count = 0
        for svc in services:
            dp = discovery_params_for_service(svc)
            if dp:
                cur.execute(RULE_DISCOVERIES_UPSERT, dp)
                count += 1
        print(f"  upserted {count} rule_discoveries rows")

        conn.commit()
        print(f"\nDONE — all changes committed.")

    except Exception as e:
        conn.rollback()
        print(f"\nERROR: {e}")
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
