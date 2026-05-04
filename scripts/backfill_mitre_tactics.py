#!/usr/bin/env python3
"""
Backfill mitre_tactics and mitre_techniques on threat_detections from check engine rule_metadata.

NOTE: Config/posture check rules (aws.accessanalyzer.*, aws.acm.*, etc.) do NOT currently have
MITRE data populated in rule_metadata — those need to be added via catalog enrichment first.
Only log-detection rules (aws.alb.alb_log.*, gcp.compute.audit.*) have MITRE data today.

Run inside the threat engine pod:
    kubectl cp scripts/backfill_mitre_tactics.py \\
        threat-engine-engines/<threat-pod>:/tmp/backfill_mitre.py
    kubectl exec -n threat-engine-engines deployment/engine-threat -- python3 /tmp/backfill_mitre.py

Dry-run:
    kubectl exec -n threat-engine-engines deployment/engine-threat -- \\
        python3 /tmp/backfill_mitre.py --dry-run

Verify only:
    kubectl exec -n threat-engine-engines deployment/engine-threat -- \\
        python3 /tmp/backfill_mitre.py --verify --tenant my-tenant
"""

import os
import json
import argparse
import sys
from typing import Dict, Any

import psycopg2
from psycopg2.extras import Json


def _check_conn():
    return psycopg2.connect(
        host=os.environ.get("CHECK_DB_HOST", os.environ.get("DB_HOST", "")),
        dbname=os.environ["CHECK_DB_NAME"],
        user=os.environ.get("CHECK_DB_USER", "postgres"),
        password=os.environ.get("CHECK_DB_PASSWORD", ""),
        sslmode="require",
    )


def _threat_conn():
    return psycopg2.connect(
        host=os.environ["THREAT_DB_HOST"],
        dbname=os.environ["THREAT_DB_NAME"],
        user=os.environ.get("THREAT_DB_USER", "postgres"),
        password=os.environ.get("THREAT_DB_PASSWORD", ""),
        sslmode="require",
    )


def get_rule_mitre_map() -> Dict[str, Dict[str, Any]]:
    """Read rule_id -> {mitre_tactics, mitre_techniques} directly from check DB rule_metadata."""
    ck = _check_conn()
    cur = ck.cursor()
    cur.execute("""
        SELECT rule_id, mitre_tactics, mitre_techniques
        FROM rule_metadata
        WHERE (mitre_tactics IS NOT NULL AND mitre_tactics != '[]'::jsonb)
           OR (mitre_techniques IS NOT NULL AND mitre_techniques != '[]'::jsonb)
    """)
    rows = cur.fetchall()
    cur.close()
    ck.close()

    mitre_map = {}
    for rule_id, tactics, techniques in rows:
        t_list = tactics if isinstance(tactics, list) else []
        tech_list = techniques if isinstance(techniques, list) else []
        if t_list or tech_list:
            mitre_map[rule_id] = {"mitre_tactics": t_list, "mitre_techniques": tech_list}

    print(f"Loaded MITRE data for {len(mitre_map)} rules from check DB rule_metadata")
    return mitre_map


def run_backfill(dry_run: bool = False) -> None:
    th = _threat_conn()
    cur = th.cursor()

    cur.execute("""
        SELECT DISTINCT rule_id FROM threat_detections
        WHERE (mitre_tactics IS NULL OR mitre_tactics = '[]'::jsonb)
          AND rule_id IS NOT NULL AND rule_id != ''
    """)
    rule_ids = [r[0] for r in cur.fetchall()]
    print(f"Found {len(rule_ids)} distinct rule_ids with empty mitre_tactics in threat_detections")

    if not rule_ids:
        print("Nothing to backfill.")
        cur.close()
        th.close()
        return

    mitre_map = get_rule_mitre_map()

    matched = [r for r in rule_ids if r in mitre_map]
    unmatched = [r for r in rule_ids if r not in mitre_map]

    print(f"Rule_ids with available MITRE data: {len(matched)}")
    print(f"Rule_ids without MITRE data in rule_metadata: {len(unmatched)}")
    if unmatched:
        print("  (Config/posture rules need MITRE enrichment in catalog first)")
        print(f"  Sample unmatched: {unmatched[:5]}")

    updated = 0
    for rule_id in matched:
        m = mitre_map[rule_id]
        tactics = json.dumps(m["mitre_tactics"])
        techniques = json.dumps(m["mitre_techniques"])

        if dry_run:
            print(f"  [DRY RUN] Would update rule_id={rule_id}: tactics={m['mitre_tactics']}")
            updated += 1
            continue

        cur.execute("""
            UPDATE threat_detections
            SET mitre_tactics = %s::jsonb,
                mitre_techniques = %s::jsonb
            WHERE rule_id = %s
              AND (mitre_tactics IS NULL OR mitre_tactics = '[]'::jsonb)
        """, (tactics, techniques, rule_id))
        updated += cur.rowcount

    if not dry_run:
        th.commit()

    cur.close()
    th.close()

    print(f"Updated: {updated} rows across {len(matched)} rule_ids")
    if dry_run:
        print("(dry-run — no changes committed)")


def verify(tenant_id: str = "") -> None:
    """Print current MITRE population stats."""
    th = _threat_conn()
    cur = th.cursor()

    tenant_clause = "WHERE tenant_id = %s" if tenant_id else ""
    params = [tenant_id] if tenant_id else []

    cur.execute(f"SELECT COUNT(*) FROM threat_detections {tenant_clause}", params)
    total = cur.fetchone()[0]

    nonempty_clause = f"{'AND' if tenant_clause else 'WHERE'} mitre_tactics != '[]'::jsonb"
    cur.execute(f"SELECT COUNT(*) FROM threat_detections {tenant_clause} {nonempty_clause}", params)
    with_mitre = cur.fetchone()[0]

    print(f"\nVerification{' for tenant ' + tenant_id if tenant_id else ''}:")
    print(f"  Total threat_detections: {total}")
    print(f"  With non-empty mitre_tactics: {with_mitre}")
    print(f"  Still empty: {total - with_mitre}")

    cur.execute("""
        SELECT rule_id, mitre_tactics, mitre_techniques
        FROM threat_detections
        WHERE mitre_tactics != '[]'::jsonb
        LIMIT 3
    """)
    rows = cur.fetchall()
    if rows:
        print("\n  Sample rows with MITRE data:")
        for row in rows:
            print(f"    rule_id={row[0]}")
            print(f"      tactics={row[1]}, techniques={row[2]}")

    cur.close()
    th.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backfill MITRE tactics/techniques on threat_detections")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without committing")
    parser.add_argument("--verify", action="store_true", help="Only verify current state, no updates")
    parser.add_argument("--tenant", default="", help="Tenant ID for verification filter")
    args = parser.parse_args()

    if args.verify:
        verify(tenant_id=args.tenant)
    else:
        run_backfill(dry_run=args.dry_run)
        verify(tenant_id=args.tenant)
