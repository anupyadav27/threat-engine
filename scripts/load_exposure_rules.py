"""
IEDS-L01: Load network exposure rules from YAML catalog into threat_engine_network.

Usage:
    python3 scripts/load_exposure_rules.py [--dry-run] [--csp aws] [--tier 1]

This script:
1. Walks catalog/rule/network_exposure/{csp}/*.yaml
2. Parses each YAML file and extracts rules[]
3. Upserts each rule into network_exposure_rules (ON CONFLICT DO UPDATE)
4. Updates di_resource_catalog.network_exposure_tier + origin_types for Tier 1 rules
5. Prints a summary of loaded/updated/skipped counts

Run this:
- After adding new YAML rules to catalog/rule/network_exposure/
- After modifying existing rules
- As part of CI/CD pipeline (--dry-run to validate before apply)

For Kubernetes:
    kubectl exec deployment/engine-network -n threat-engine-engines -- python3 -c "
        import subprocess; subprocess.run(['python3', '/app/scripts/load_exposure_rules.py'])
    "
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
import yaml


CATALOG_ROOT = Path(__file__).parent.parent / "catalog" / "rule" / "network_exposure"

VALID_CSPS = {"aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s", "all"}
VALID_TIERS = {1, 2, 3}
VALID_ORIGINS = {
    "internet", "vpn", "connected_network",
    "direct_connect", "external_iam", "supply_chain",
}


def _get_network_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["NETWORK_DB_HOST"],
        dbname="threat_engine_network",
        user=os.environ["NETWORK_DB_USER"],
        password=os.environ["NETWORK_DB_PASSWORD"],
        port=int(os.environ.get("NETWORK_DB_PORT", "5432")),
        connect_timeout=10,
    )


def _get_di_conn() -> psycopg2.extensions.connection:
    host = os.environ.get("DI_DB_HOST") or os.environ.get("DISCOVERIES_DB_HOST")
    user = os.environ.get("DI_DB_USER") or os.environ.get("DISCOVERIES_DB_USER")
    pwd = os.environ.get("DI_DB_PASSWORD") or os.environ.get("DISCOVERIES_DB_PASSWORD")
    if not host:
        raise RuntimeError("DI_DB_HOST / DISCOVERIES_DB_HOST not set")
    return psycopg2.connect(
        host=host, dbname="threat_engine_di",
        user=user, password=pwd, port=5432, connect_timeout=10,
    )


def _validate_rule(rule: Dict[str, Any], source_file: str) -> Optional[str]:
    for required in ("rule_id", "tier", "csp", "resource_type", "origin_type", "title"):
        if required not in rule:
            return f"missing required field '{required}' in {source_file}"
    if rule["tier"] not in VALID_TIERS:
        return f"invalid tier={rule['tier']} in {source_file}"
    if rule["csp"] not in VALID_CSPS:
        return f"invalid csp={rule['csp']} in {source_file}"
    if rule["origin_type"] not in VALID_ORIGINS:
        return f"invalid origin_type={rule['origin_type']} in {source_file}"
    return None


def load_yaml_files(
    csp_filter: Optional[str] = None,
    tier_filter: Optional[int] = None,
) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    search_root = CATALOG_ROOT / csp_filter if csp_filter else CATALOG_ROOT

    for yaml_path in sorted(search_root.rglob("*.yaml")):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        if not data or "rules" not in data:
            continue
        for rule in data["rules"]:
            if tier_filter and rule.get("tier") != tier_filter:
                continue
            error = _validate_rule(rule, str(yaml_path))
            if error:
                print(f"  [SKIP] {error}")
                continue
            rule["_source_file"] = str(yaml_path.relative_to(CATALOG_ROOT.parent.parent))
            rules.append(rule)

    return rules


def upsert_rules(
    rules: List[Dict[str, Any]],
    dry_run: bool = False,
) -> Dict[str, int]:
    if not rules:
        return {"inserted": 0, "updated": 0, "skipped": 0}

    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            inserted = updated = skipped = 0
            for rule in rules:
                cur.execute(
                    "SELECT updated_at FROM network_exposure_rules WHERE rule_id = %s",
                    (rule["rule_id"],),
                )
                existing = cur.fetchone()

                params = (
                    rule["rule_id"],
                    rule["tier"],
                    rule["csp"],
                    rule["resource_type"],
                    rule["origin_type"],
                    rule["title"],
                    rule.get("description"),
                    rule.get("severity", "high"),
                    rule.get("required_emitted_fields") or [],
                    psycopg2.extras.Json(rule.get("exposure_conditions") or []),
                    psycopg2.extras.Json(rule.get("traversal_steps") or []),
                    rule.get("_source_file"),
                )

                if not dry_run:
                    cur.execute(
                        """
                        INSERT INTO network_exposure_rules
                            (rule_id, tier, csp, resource_type, origin_type, title,
                             description, severity, required_emitted_fields,
                             exposure_conditions, traversal_steps, loaded_from,
                             loaded_at, updated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
                        ON CONFLICT (rule_id) DO UPDATE SET
                            tier                    = EXCLUDED.tier,
                            csp                     = EXCLUDED.csp,
                            resource_type           = EXCLUDED.resource_type,
                            origin_type             = EXCLUDED.origin_type,
                            title                   = EXCLUDED.title,
                            description             = EXCLUDED.description,
                            severity                = EXCLUDED.severity,
                            required_emitted_fields = EXCLUDED.required_emitted_fields,
                            exposure_conditions     = EXCLUDED.exposure_conditions,
                            traversal_steps         = EXCLUDED.traversal_steps,
                            loaded_from             = EXCLUDED.loaded_from,
                            updated_at              = NOW()
                        """,
                        params,
                    )

                if existing is None:
                    inserted += 1
                    action = "INSERT"
                else:
                    updated += 1
                    action = "UPDATE"

                print(f"  [{action}] {rule['rule_id']:30s} tier={rule['tier']} csp={rule['csp']:8s} {rule['resource_type']}")

        if not dry_run:
            conn.commit()
        else:
            conn.rollback()

        return {"inserted": inserted, "updated": updated, "skipped": skipped}
    finally:
        conn.close()


def update_di_catalog_tier1(
    rules: List[Dict[str, Any]],
    dry_run: bool = False,
) -> int:
    """For Tier 1 rules: set network_exposure_tier + origin_types in di_resource_catalog."""
    tier1_rules = [r for r in rules if r["tier"] == 1]
    if not tier1_rules:
        return 0

    from collections import defaultdict
    # Group by (csp, resource_type): collect all origin_types
    catalog_updates: Dict[tuple, set] = defaultdict(set)
    for rule in tier1_rules:
        catalog_updates[(rule["csp"], rule["resource_type"])].add(rule["origin_type"])

    conn = _get_di_conn()
    updated = 0
    try:
        with conn.cursor() as cur:
            for (csp, resource_type), origin_types in catalog_updates.items():
                if not dry_run:
                    cur.execute(
                        """
                        UPDATE di_resource_catalog
                           SET network_exposure_tier = 1,
                               origin_types = %s::jsonb,
                               updated_at   = NOW()
                         WHERE csp = %s
                           AND resource_type = %s
                        """,
                        (
                            psycopg2.extras.Json(sorted(origin_types)),
                            csp,
                            resource_type,
                        ),
                    )
                    updated += cur.rowcount
                else:
                    cur.execute(
                        "SELECT COUNT(*) FROM di_resource_catalog WHERE csp=%s AND resource_type=%s",
                        (csp, resource_type),
                    )
                    row = cur.fetchone()
                    if row and row[0] > 0:
                        updated += 1
                        print(f"  [DI-UPDATE] {csp}:{resource_type} → tier=1 origins={sorted(origin_types)}")
                    else:
                        print(f"  [DI-MISS]   {csp}:{resource_type} not found in di_resource_catalog")

        if not dry_run:
            conn.commit()
        else:
            conn.rollback()

        return updated
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Load IEDS exposure rules into threat_engine_network")
    parser.add_argument("--dry-run", action="store_true", help="Validate + print without writing to DB")
    parser.add_argument("--csp", help="Load only rules for this CSP (aws/azure/gcp/...)")
    parser.add_argument("--tier", type=int, help="Load only rules for this tier (1/2/3)")
    args = parser.parse_args()

    print(f"Loading IEDS rules from {CATALOG_ROOT}")
    if args.dry_run:
        print("  [DRY-RUN mode — no DB writes]")

    rules = load_yaml_files(csp_filter=args.csp, tier_filter=args.tier)
    print(f"\nFound {len(rules)} rules across all YAML files")

    if not rules:
        print("Nothing to load.")
        sys.exit(0)

    # --- Upsert into network_exposure_rules ---
    print("\n--- network_exposure_rules (threat_engine_network) ---")
    counts = upsert_rules(rules, dry_run=args.dry_run)
    print(f"  inserted={counts['inserted']} updated={counts['updated']} skipped={counts['skipped']}")

    # --- Update di_resource_catalog for Tier 1 ---
    print("\n--- di_resource_catalog (threat_engine_di) Tier 1 updates ---")
    di_updated = update_di_catalog_tier1(rules, dry_run=args.dry_run)
    print(f"  rows updated={di_updated}")

    print("\nDONE")


if __name__ == "__main__":
    main()
