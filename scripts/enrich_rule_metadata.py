#!/usr/bin/env python3
"""
Enrich rule_metadata with content from backup metadata YAML files.

For each rule with NULL/empty rationale, remediation, description, or references,
looks up the corresponding metadata YAML from the engine's metadata directory
(or Feb backup) and patches those fields.

Usage:
  python3 scripts/enrich_rule_metadata.py [--dry-run] [--csp aws]
"""

import os, glob, yaml, json, psycopg2, argparse
from pathlib import Path

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# Primary source: engine check metadata dirs
ENGINE_METADATA_DIRS = {
    "aws":      "/Users/apple/Desktop/threat-engine/engines/check/engine_check_aws/services",
    "gcp":      "/Users/apple/Desktop/threat-engine/engines/check/engine_check_gcp/services",
    "azure":    "/Users/apple/Desktop/threat-engine/engines/check/engine_check_azure/services",
    "oci":      "/Users/apple/Desktop/threat-engine/engines/check/engine_check_oci/services",
    "ibm":      "/Users/apple/Desktop/threat-engine/engines/check/engine_check_ibm/services",
    "alicloud": "/Users/apple/Desktop/threat-engine/engines/check/engine_check_alicloud/services",
    "k8s":      "/Users/apple/Desktop/threat-engine/engines/check/engine_check_k8s/services",
}

# Fallback: Feb backup metadata dirs
BACKUP_METADATA_DIRS = {
    "aws":      "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_aws/input/rule_db/default/services",
    "gcp":      "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_gcp/input/rule_db/default/services",
    "azure":    "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_azure/input/rule_db/default/services",
    "oci":      "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_oci/input/rule_db/default/services",
    "ibm":      "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_ibm/input/rule_db/default/services",
    "alicloud": "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_alicloud/input/rule_db/default/services",
    "k8s":      "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input/engine_configscan_k8s/input/rule_db/default/services",
}


def load_metadata_index(csp: str) -> dict:
    """
    Load all metadata YAMLs for a CSP.
    Returns {rule_id: metadata_dict}
    """
    meta = {}
    for base_dir in [ENGINE_METADATA_DIRS.get(csp), BACKUP_METADATA_DIRS.get(csp)]:
        if not base_dir or not os.path.isdir(base_dir):
            continue
        for mf in glob.glob(f"{base_dir}/**/metadata/*.yaml", recursive=True):
            try:
                with open(mf) as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                rid = data.get('rule_id') or Path(mf).stem
                if rid and rid not in meta:
                    meta[rid] = data
            except Exception:
                continue
    return meta


def load_db_rules(conn, csp: str) -> list:
    """Load rules that need enrichment for a CSP."""
    cur = conn.cursor()
    cur.execute("""
        SELECT rule_id, title, description, rationale, remediation, severity,
               domain, subcategory, "references"
        FROM rule_metadata
        WHERE provider = %s
          AND customer_id IS NULL
          AND (
               rationale IS NULL OR rationale = '' OR
               remediation IS NULL OR remediation = '' OR
               description IS NULL OR description = ''
          )
    """, (csp,))
    rows = cur.fetchall()
    cur.close()
    cols = ['rule_id','title','description','rationale','remediation','severity',
            'domain','subcategory','references']
    return [dict(zip(cols, r)) for r in rows]


UPDATE_SQL = """
    UPDATE rule_metadata SET
        title        = COALESCE(NULLIF(title, ''), %(title)s),
        description  = COALESCE(NULLIF(description, ''), %(description)s),
        rationale    = COALESCE(NULLIF(rationale, ''), %(rationale)s),
        remediation  = COALESCE(NULLIF(remediation, ''), %(remediation)s),
        domain       = COALESCE(NULLIF(domain, ''), %(domain)s),
        subcategory  = COALESCE(NULLIF(subcategory, ''), %(subcategory)s),
        "references"  = CASE
            WHEN "references" IS NULL OR "references"::text IN ('null', '[]')
            THEN %(references)s::jsonb
            ELSE "references"
        END,
        updated_at   = NOW()
    WHERE rule_id = %(rule_id)s AND customer_id IS NULL
"""


def enrich_csp(csp: str, conn, dry_run: bool):
    print(f"\n{'='*60}")
    print(f"  CSP: {csp.upper()}")
    print(f"{'='*60}")

    meta_index = load_metadata_index(csp)
    print(f"  Loaded {len(meta_index)} metadata files")

    db_rules = load_db_rules(conn, csp)
    print(f"  Rules needing enrichment: {len(db_rules)}")

    updated = 0
    no_meta = 0

    for rule in db_rules:
        rule_id = rule['rule_id']
        m = meta_index.get(rule_id)
        if not m:
            no_meta += 1
            continue

        refs = m.get('references', [])
        if isinstance(refs, str):
            refs = [refs]
        elif not isinstance(refs, list):
            refs = []

        severity = m.get('severity', rule['severity'] or 'medium').lower()
        if severity not in ('critical','high','medium','low','informational'):
            severity = 'medium'

        params = {
            'rule_id':     rule_id,
            'title':       m.get('title') or rule['title'] or rule_id,
            'description': m.get('description', ''),
            'rationale':   m.get('rationale', ''),
            'remediation': m.get('remediation', ''),
            'domain':      m.get('domain', 'security_configuration'),
            'subcategory': m.get('subcategory', 'configuration_baseline'),
            'references':  json.dumps(refs),
        }

        if dry_run:
            if updated < 3:
                print(f"  [DRY] {rule_id}")
                print(f"        rationale: {(params['rationale'] or '')[:80]}")
        else:
            cur = conn.cursor()
            cur.execute(UPDATE_SQL, params)
            conn.commit()
            cur.close()

        updated += 1

    print(f"  Updated: {updated} | No metadata found: {no_meta}")
    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--csp', default=None)
    args = parser.parse_args()

    conn = psycopg2.connect(**DB_CONFIG)
    csps = [args.csp] if args.csp else list(ENGINE_METADATA_DIRS.keys())

    total = 0
    for csp in csps:
        total += enrich_csp(csp, conn, args.dry_run)

    conn.close()
    print(f"\n{'='*60}")
    print(f"  TOTAL rules enriched: {total}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
