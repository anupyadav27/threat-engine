#!/usr/bin/env python3
"""
Update 92 GCP rule_checks where S3 data has better conditions than DB.
Only updates rules where S3 score > DB score (never downgrades).

Usage:
  python3 scripts/update_gcp_s3_checks.py [--dry-run]
"""

import yaml, json, psycopg2, argparse, re
from pathlib import Path

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

GCP_BASE = Path("/Users/apple/Desktop/threat-engine-s3-input/engine_check_gcp/input/rule_db/default/services")


def score_condition(cond):
    if not cond:
        return 0
    if 'all' in cond or 'any' in cond:
        sub = cond.get('all') or cond.get('any')
        if not sub:
            return 0
        real = any(
            c.get('op') not in ('exists',) or c.get('value') not in (None, 'null', True, 'true')
            for c in sub if isinstance(c, dict)
        )
        return 2 if real else 1
    if 'conditions' in cond:
        return 2
    op = cond.get('op', '')
    val = cond.get('value')
    if op == 'exists' and val in (None, 'null', True, 'true'):
        return 1
    if op:
        return 2
    return 0


def convert_calls_to_conditions(calls, logic='AND'):
    """Convert S3 calls/fields format to engine's all/any format (not op/conditions)."""
    all_fields = []
    for call in calls:
        for f in call.get('fields', []):
            cond = {'op': f.get('operator', 'equals'), 'var': f'item.{f["path"]}'}
            if 'expected' in f:
                cond['value'] = f['expected']
            if f.get('negate'):
                cond['negate'] = True
            all_fields.append(cond)
    if not all_fields:
        return {}
    if len(all_fields) == 1:
        return all_fields[0]
    # Engine uses {"all":[...]} / {"any":[...]} NOT {"op":"and","conditions":[...]}
    key = 'all' if logic.upper() == 'AND' else 'any'
    return {key: all_fields}


def load_gcp_s3_rules():
    rules = {}
    for yaml_file in GCP_BASE.rglob("*_rules.yaml"):
        if 'metadata' in str(yaml_file):
            continue
        try:
            with open(yaml_file) as f:
                content = '\n'.join(l for l in f.readlines() if not l.startswith('#'))
            data = yaml.safe_load(content)
            if not data:
                continue
            for top_key, svc_data in data.items():
                if not isinstance(svc_data, dict):
                    continue
                for c in svc_data.get('checks', []):
                    rid = c.get('check_id') or c.get('rule_id')
                    if rid and ',' not in str(rid):
                        calls = c.get('calls', [])
                        cond = convert_calls_to_conditions(calls, c.get('logic', 'AND'))
                        rules[rid] = {
                            'for_each':   c.get('for_each', ''),
                            'conditions': cond,
                        }
        except Exception:
            pass
    return rules


def run(dry_run: bool):
    s3_rules = load_gcp_s3_rules()
    print(f"GCP S3 rules loaded: {len(s3_rules)}")

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT rc.rule_id, rc.check_config
        FROM rule_checks rc
        JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
        WHERE rm.provider = 'gcp' AND rm.customer_id IS NULL
          AND rc.rule_id = ANY(%s)
    """, (list(s3_rules.keys()),))
    db_checks = {r[0]: r[1] for r in cur.fetchall()}

    to_update = []
    for rid, s3_data in s3_rules.items():
        if rid not in db_checks:
            continue
        db_cfg = db_checks[rid] or {}
        db_cond = db_cfg.get('conditions', {})
        s3_cond = s3_data['conditions']

        # Only update rules where DB has EMPTY conditions and S3 has real ones.
        # Skip format-only differences (all/any in DB is correct engine format).
        db_empty = not db_cond or db_cond == {}
        s3_has_content = bool(s3_cond and s3_cond != {})

        if db_empty and s3_has_content:
            existing_fe = db_cfg.get('for_each', '')
            new_fe = s3_data['for_each'] or existing_fe
            new_cfg = {'for_each': new_fe, 'conditions': s3_cond}
            to_update.append((rid, new_cfg, db_cond, s3_cond))

    print(f"Rules to upgrade: {len(to_update)}")

    if dry_run:
        for rid, new_cfg, old_cond, new_cond in to_update[:5]:
            print(f"\n  {rid}")
            print(f"    OLD: {json.dumps(old_cond)[:100]}")
            print(f"    NEW: {json.dumps(new_cond)[:100]}")
        return

    updated = 0
    for rid, new_cfg, _, _ in to_update:
        cur.execute("""
            UPDATE rule_checks SET
                check_config = %s::jsonb,
                updated_at   = NOW()
            WHERE rule_id = %s
        """, (json.dumps(new_cfg), rid))
        if cur.rowcount:
            updated += 1

    conn.commit()
    print(f"Updated: {updated} GCP rules")
    cur.close()
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    run(args.dry_run)
