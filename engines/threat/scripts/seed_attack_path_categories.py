#!/usr/bin/env python3
"""
Seed attack_path_category on resource_relationship_rules.

Classifies all 38 RelationType values into attack-path categories:
  - exposure:             Internet entry points
  - lateral_movement:     Network/compute pivot
  - privilege_escalation: Permission gain
  - data_access:          Data read/write/exfiltration
  - execution:            Code execution triggers
  - data_flow:            Message/event flow
  - NULL:                 Not an attack path (defensive/organizational)

Run:
    python seed_attack_path_categories.py
    python seed_attack_path_categories.py --db-host <host> --db-port 5432
"""

import argparse
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Classification Map ──────────────────────────────────────────────────────
# Key = relation_type value from RelationType enum
# Value = attack_path_category (NULL means not an attack path)

ATTACK_PATH_CLASSIFICATION = {
    # -- Exposure: Internet entry points --
    "internet_connected":    "exposure",
    "exposed_through":       "exposure",
    "serves_traffic_for":    "exposure",

    # -- Lateral movement: Network/compute pivot --
    "connected_to":          "lateral_movement",
    "routes_to":             "lateral_movement",
    "allows_traffic_from":   "lateral_movement",
    "attached_to":           "lateral_movement",
    "runs_on":               "lateral_movement",

    # -- Privilege escalation: Permission gain --
    "assumes":               "privilege_escalation",
    "has_policy":            "privilege_escalation",
    "grants_access_to":      "privilege_escalation",

    # -- Data access: Data read/write/exfiltration --
    "stores_data_in":        "data_access",
    "backs_up_to":           "data_access",
    "replicates_to":         "data_access",
    "cached_by":             "data_access",

    # -- Execution: Code execution triggers --
    "triggers":              "execution",
    "invokes":               "execution",
    "uses":                  "execution",

    # -- Data flow: Message/event flow --
    "publishes_to":          "data_flow",
    "subscribes_to":         "data_flow",
    "resolves_to":           "data_flow",

    # -- NOT attack paths (defensive / organizational / operational) --
    "contained_by":          None,
    "controlled_by":         None,
    "encrypted_by":          None,
    "logging_enabled_to":    None,
    "monitored_by":          None,
    "member_of":             None,
    "scales_with":           None,
    "manages":               None,
    "deployed_by":           None,
    "depends_on":            None,
    "authenticated_by":      None,
    "protected_by":          None,
    "scanned_by":            None,
    "complies_with":         None,

    # -- Layer types (network infrastructure — not attack paths) --
    "1st_layer":             None,
    "2nd_layer":             None,
    "3rd_layer":             None,
    "4th_layer":             None,
    "on_prem_datacenter":    None,
}


def _conn_string(args) -> str:
    host = args.db_host or os.getenv("INVENTORY_DB_HOST", "localhost")
    port = args.db_port or os.getenv("INVENTORY_DB_PORT", "5432")
    db = args.db_name or os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
    user = args.db_user or os.getenv("INVENTORY_DB_USER", "inventory_user")
    pwd = args.db_password or os.getenv("INVENTORY_DB_PASSWORD", "inventory_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def seed(args):
    import psycopg2

    conn_str = _conn_string(args)
    logger.info(f"Connecting to: {conn_str.split('@')[1]}")
    conn = psycopg2.connect(conn_str)

    try:
        # First, add column if it doesn't exist
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'resource_relationship_rules'
                  AND column_name = 'attack_path_category'
            """)
            if not cur.fetchone():
                logger.info("Adding attack_path_category column...")
                cur.execute("""
                    ALTER TABLE resource_relationship_rules
                    ADD COLUMN attack_path_category VARCHAR(50)
                """)
                conn.commit()
                logger.info("Column added.")
            else:
                logger.info("Column attack_path_category already exists.")

        # Update each relation_type with its category
        updated = 0
        skipped = 0
        with conn.cursor() as cur:
            for relation_type, category in ATTACK_PATH_CLASSIFICATION.items():
                cur.execute("""
                    UPDATE resource_relationship_rules
                    SET    attack_path_category = %s,
                           updated_at = NOW()
                    WHERE  relation_type = %s
                      AND  (attack_path_category IS DISTINCT FROM %s)
                """, (category, relation_type, category))
                rows = cur.rowcount
                if rows > 0:
                    updated += rows
                    logger.info(f"  {relation_type:30s} → {category or 'NULL':25s} ({rows} rules)")
                else:
                    skipped += 1

        conn.commit()
        logger.info(f"Done. Updated: {updated} rules, Skipped (already correct): {skipped} types")

        # Summary
        with conn.cursor() as cur:
            cur.execute("""
                SELECT attack_path_category, COUNT(*)
                FROM resource_relationship_rules
                WHERE is_active = TRUE
                GROUP BY attack_path_category
                ORDER BY attack_path_category NULLS LAST
            """)
            logger.info("\n── Summary ──")
            for row in cur.fetchall():
                cat = row[0] or "NULL (not attack path)"
                logger.info(f"  {cat:30s} {row[1]:5d} rules")

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Seed attack_path_category on resource_relationship_rules")
    parser.add_argument("--db-host", help="DB host (or INVENTORY_DB_HOST env)")
    parser.add_argument("--db-port", help="DB port (or INVENTORY_DB_PORT env)")
    parser.add_argument("--db-name", help="DB name (or INVENTORY_DB_NAME env)")
    parser.add_argument("--db-user", help="DB user (or INVENTORY_DB_USER env)")
    parser.add_argument("--db-password", help="DB password (or INVENTORY_DB_PASSWORD env)")
    args = parser.parse_args()
    seed(args)


if __name__ == "__main__":
    main()
