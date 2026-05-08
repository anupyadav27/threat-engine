#!/usr/bin/env python3
"""
Enrich rule_metadata from S3-downloaded metadata YAML files.
Fills rationale, description, remediation, references, severity, domain, subcategory
using real S3 content — only writes to NULL/empty fields (never overwrites existing data).

Sources:
  /Users/apple/Desktop/threat-engine-s3-input/engine_check_{csp}/input/rule_db/default/services/*/metadata/*.yaml

Usage:
  python3 scripts/enrich_metadata_from_s3.py [--dry-run] [--csp gcp]
"""

import yaml, json, psycopg2, argparse
from pathlib import Path
from collections import defaultdict

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

BASE = Path("/Users/apple/Desktop/threat-engine-s3-input")

CSP_DIRS = {
    'gcp':      BASE / 'engine_check_gcp/input/rule_db/default/services',
    'ibm':      BASE / 'engine_check_ibm/input/rule_db/default/services',
    'alicloud': BASE / 'engine_check_alicloud/input/rule_db/default/services',
    'k8s':      BASE / 'engine_check_k8s/input/rule_db/default/services',
    'azure':    BASE / 'engine_check_azure/input/rule_db/default/services',
    'oci':      BASE / 'engine_check_oci/input/rule_db/default/services',
    'aws':      BASE / 'engine_check/engine_check_aws/services',
}


def load_s3_metadata(csp: str) -> dict:
    """Load all metadata YAMLs for a CSP. Returns {rule_id: metadata_dict}."""
    svc_root = CSP_DIRS.get(csp)
    if not svc_root or not svc_root.exists():
        return {}

    metadata = {}
    for yaml_file in svc_root.rglob("metadata/*.yaml"):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                continue
            rule_id = data.get('rule_id', '')
            if rule_id:
                metadata[rule_id] = data
        except Exception:
            pass
    return metadata


# S3 is authoritative for core content fields — always overwrite when S3 has content.
# mitre_tactics and compliance_frameworks are generated/supplementary — only fill if empty.
UPDATE_SQL = """
    UPDATE rule_metadata SET
        title         = CASE WHEN %(title)s != ''       THEN %(title)s       ELSE title       END,
        description   = CASE WHEN %(description)s != '' THEN %(description)s ELSE description END,
        rationale     = CASE WHEN %(rationale)s != ''   THEN %(rationale)s   ELSE rationale   END,
        remediation   = CASE WHEN %(remediation)s != '' THEN %(remediation)s ELSE remediation END,
        severity      = CASE WHEN %(severity)s != ''    THEN %(severity)s    ELSE severity    END,
        domain        = CASE WHEN %(domain)s != ''      THEN %(domain)s      ELSE domain      END,
        subcategory   = CASE WHEN %(subcategory)s != '' THEN %(subcategory)s ELSE subcategory END,
        "references"  = CASE
            WHEN %(references)s::jsonb::text NOT IN ('null','[]')
            THEN %(references)s::jsonb
            ELSE "references"
        END,
        -- mitre + compliance: supplementary only — never overwrite existing
        mitre_tactics = CASE
            WHEN mitre_tactics IS NULL OR mitre_tactics::text IN ('null','[]')
            THEN %(mitre_tactics)s::jsonb
            ELSE mitre_tactics
        END,
        compliance_frameworks = CASE
            WHEN compliance_frameworks IS NULL OR compliance_frameworks::text IN ('null','[]','{}')
            THEN %(compliance_frameworks)s::jsonb
            ELSE compliance_frameworks
        END,
        updated_at    = NOW()
    WHERE rule_id = %(rule_id)s
      AND customer_id IS NULL
"""


def build_remediation(meta: dict) -> str:
    """Build remediation from description field if not provided."""
    desc = meta.get('description', '')
    if not desc:
        return ''
    # description often contains remediation steps already
    return desc


def run(csps: list, dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    total_updated = 0

    for csp in csps:
        print(f"\n=== {csp.upper()} ===")
        s3_meta = load_s3_metadata(csp)
        print(f"  S3 metadata YAMLs loaded: {len(s3_meta)}")

        if not s3_meta:
            print("  No metadata found, skipping")
            continue

        # Get ALL DB rules for this CSP (S3 is authoritative — update everything)
        cur.execute("""
            SELECT rule_id FROM rule_metadata
            WHERE provider = %s AND customer_id IS NULL
        """, (csp,))
        db_rules = {r[0] for r in cur.fetchall()}
        print(f"  DB rules for CSP: {len(db_rules)}")

        # Match and update
        matched = 0
        updated = 0
        no_match = 0

        for rule_id in db_rules:
            s3 = s3_meta.get(rule_id)
            if not s3:
                no_match += 1
                continue

            matched += 1

            refs = s3.get('references', [])
            if isinstance(refs, str):
                refs = [refs]

            remediation = s3.get('remediation', '') or build_remediation(s3)

            # mitre and compliance from S3 if present
            mitre = s3.get('mitre_tactics', s3.get('mitre', []))
            if isinstance(mitre, str):
                mitre = [mitre]
            compliance = s3.get('compliance_frameworks', s3.get('compliance', []))
            if isinstance(compliance, str):
                compliance = [compliance]

            params = {
                'rule_id':              rule_id,
                'title':                (s3.get('title') or '')[:500],
                'description':          s3.get('description', ''),
                'rationale':            s3.get('rationale', ''),
                'remediation':          remediation,
                'severity':             s3.get('severity', ''),
                'domain':               s3.get('domain', ''),
                'subcategory':          s3.get('subcategory', ''),
                'references':           json.dumps(refs),
                'mitre_tactics':        json.dumps(mitre),
                'compliance_frameworks':json.dumps(compliance),
            }

            if dry_run:
                if updated < 2:
                    print(f"  [DRY] {rule_id}")
                    print(f"        rationale:   {s3.get('rationale','')[:80]}...")
                    print(f"        remediation: {remediation[:80]}...")
                    print(f"        domain:      {s3.get('domain','')} | severity: {s3.get('severity','')}")
                updated += 1
                continue

            cur.execute(UPDATE_SQL, params)
            if cur.rowcount:
                updated += 1

        if not dry_run:
            conn.commit()

        print(f"  Matched in S3: {matched} | Updated: {updated} | No S3 match: {no_match}")
        total_updated += updated

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Total updated: {total_updated}")
    cur.close()
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--csp', default=None, help='Comma-separated CSPs, e.g. gcp,ibm')
    args = parser.parse_args()

    all_csps = ['gcp', 'ibm', 'alicloud', 'k8s', 'azure', 'oci', 'aws']
    csps = [c.strip() for c in args.csp.split(',')] if args.csp else all_csps
    run(csps, args.dry_run)
