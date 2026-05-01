#!/usr/bin/env python3
"""
Enrich rule_metadata.compliance_frameworks from lab-main compliance mapping JSONs.

For each CSP, reads the function_to_compliance_mapping JSON, matches function names
to DB rule IDs using fuzzy normalization, and updates compliance_frameworks JSONB.

Matching strategy:
  1. Normalize function name tokens (provider, service, check parts)
  2. Find DB rules with same provider+service prefix
  3. Score by token overlap; best match wins if score >= threshold

Usage:
  python3 scripts/enrich_compliance_frameworks.py [--dry-run] [--csp aws]
"""

import os, re, json, psycopg2, psycopg2.extras, argparse
from collections import defaultdict

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

LAB_BASE = "/Users/apple/Desktop/lab-main/rule_finalisation/rule_list/csp_rules_2025-11-13"

# Map our provider names → lab-main folder names
CSP_FOLDER = {
    "aws":      "aws",
    "azure":    "azure",
    "gcp":      "gcp",
    "alicloud": "alicloud",
    "ibm":      "ibm",
    "k8s":      "k8s",
    "oci":      "oracle",
}

# Stopwords — skip these when token-matching (too common to be discriminating)
STOPWORDS = {
    'enabled', 'check', 'list', 'get', 'describe', 'find', 'ensure',
    'should', 'must', 'required', 'configured', 'verified', 'audit',
    'is', 'are', 'the', 'to', 'for', 'and', 'or', 'in', 'of', 'with',
}


def normalize(s: str) -> str:
    """Lowercase, strip non-alphanumeric."""
    return re.sub(r'[^a-z0-9]', '', s.lower())


def tokenize(func_name: str) -> list:
    """Split function name into meaningful tokens."""
    parts = re.split(r'[._\-]', func_name.lower())
    tokens = []
    for p in parts:
        # Also split camelCase
        sub = re.findall(r'[a-z0-9]+', p)
        tokens.extend(sub)
    return [t for t in tokens if len(t) > 2 and t not in STOPWORDS]


def load_mapping(csp: str) -> dict:
    """
    Returns {function_name: [compliance_fw_id, ...]}
    Handles comma-separated multi-function keys by splitting them.
    """
    folder = CSP_FOLDER.get(csp)
    if not folder:
        return {}
    fpath = os.path.join(LAB_BASE, folder, f"{folder}_function_to_compliance_mapping_2025-11-13.json")
    if not os.path.exists(fpath):
        return {}
    with open(fpath) as f:
        raw = json.load(f)

    result = defaultdict(set)
    for key, fw_ids in raw.items():
        if not isinstance(fw_ids, list):
            fw_ids = [fw_ids]
        # Split comma-separated multi-function keys
        functions = [k.strip() for k in key.split(',')]
        for func in functions:
            if func:
                for fw in fw_ids:
                    if fw:
                        result[func].add(fw)

    return {k: sorted(v) for k, v in result.items()}


def load_db_rules(conn, csp: str) -> dict:
    """Returns {rule_id: {service, compliance_frameworks_existing}} for a CSP."""
    cur = conn.cursor()
    cur.execute(
        "SELECT rule_id, service, compliance_frameworks FROM rule_metadata WHERE provider=%s",
        (csp,)
    )
    rules = {}
    for rule_id, service, cf in cur.fetchall():
        existing_fw = []
        if cf and cf != 'null':
            if isinstance(cf, list):
                existing_fw = cf
            elif isinstance(cf, dict):
                existing_fw = cf.get('frameworks', [cf]) if 'frameworks' not in cf else cf['frameworks']
        rules[rule_id] = {'service': service or '', 'existing_fw': existing_fw}
    cur.close()
    return rules


def extract_service(func_name: str, csp: str) -> str:
    """Extract service from function name."""
    parts = func_name.strip().split('.')
    # Remove provider prefix
    if parts and parts[0] == csp:
        parts = parts[1:]
    if parts and parts[0] in ('paas', 'saas', 'csp', 'cloud'):
        parts = parts[1:]
    return parts[0] if parts else ''


def match_function_to_rules(func_name: str, csp: str, db_rules: dict) -> list:
    """
    Find DB rule IDs that best match this function name.
    Returns list of (rule_id, score) sorted by score desc.
    """
    svc = extract_service(func_name, csp)
    func_tokens = set(tokenize(func_name))
    # Add significant whole-word tokens from the last segment
    parts = func_name.split('.')
    last_part = parts[-1] if parts else ''
    last_tokens = set(re.split(r'_', last_part.lower()))
    func_tokens.update(t for t in last_tokens if len(t) > 2 and t not in STOPWORDS)

    if not func_tokens:
        return []

    # Try exact match first
    if func_name in db_rules:
        return [(func_name, 10)]

    # Prefix match: rule_id starts with csp.service
    prefix = f"{csp}.{svc}."
    candidates = [r for r in db_rules if r.startswith(prefix)]
    if not candidates:
        # Broaden: any rule containing the service name
        candidates = [r for r in db_rules if f'.{svc}.' in r or r.startswith(f'{csp}.{svc}')]
    if not candidates:
        # Fallback: all rules for this provider
        candidates = list(db_rules.keys())

    scored = []
    for rule_id in candidates:
        rule_tokens = set(tokenize(rule_id))
        # Add tokens from the last segment of rule_id
        rule_parts = rule_id.split('.')
        rule_last = rule_parts[-1] if rule_parts else ''
        rule_last_tokens = set(re.split(r'_', rule_last.lower()))
        rule_tokens.update(t for t in rule_last_tokens if len(t) > 2 and t not in STOPWORDS)

        if not rule_tokens:
            continue

        overlap = func_tokens & rule_tokens
        score = len(overlap) / max(len(func_tokens), 1)

        # Bonus: exact service match
        if f'.{svc}.' in rule_id:
            score += 0.3

        # Bonus: last segment tokens mostly overlap
        last_overlap = last_tokens & rule_last_tokens
        if last_tokens and len(last_overlap) / len(last_tokens) >= 0.5:
            score += 0.4

        if score >= 0.5:
            scored.append((rule_id, round(score, 3)))

    return sorted(scored, key=lambda x: -x[1])


def build_compliance_update(csp: str, mapping: dict, db_rules: dict,
                             dry_run: bool = False) -> dict:
    """
    Returns {rule_id: [compliance_fw_ids]} for rules that should be updated.
    Each rule gets the UNION of all matching function's compliance IDs.
    """
    # For each DB rule, collect compliance IDs from all functions that match it
    rule_to_fw = defaultdict(set)

    # Also build reverse: for each function, find best matching rule
    match_count = 0
    no_match = 0

    for func_name, fw_ids in mapping.items():
        matches = match_function_to_rules(func_name, csp, db_rules)
        if not matches:
            no_match += 1
            continue

        # Take top match if score is high enough
        best_rule, best_score = matches[0]
        if best_score >= 0.5:
            rule_to_fw[best_rule].update(fw_ids)
            match_count += 1
            # Also map secondary matches if score is close to best
            for rule_id, score in matches[1:5]:
                if score >= 0.7 and score >= best_score * 0.8:
                    rule_to_fw[rule_id].update(fw_ids)

    print(f"  Functions matched: {match_count} / {len(mapping)} (no_match={no_match})")

    # Only update rules where we have new compliance frameworks to add
    to_update = {}
    for rule_id, new_fws in rule_to_fw.items():
        if rule_id not in db_rules:
            continue
        existing = set(db_rules[rule_id]['existing_fw'])
        combined = existing | new_fws
        if combined != existing:
            to_update[rule_id] = sorted(combined)

    return to_update


def apply_updates(conn, csp: str, updates: dict, dry_run: bool):
    """Apply compliance_frameworks updates to DB."""
    if not updates:
        print(f"  No updates needed for {csp}")
        return

    print(f"  Updating {len(updates)} rules with compliance frameworks...")
    if dry_run:
        sample = list(updates.items())[:3]
        for rule_id, fws in sample:
            print(f"  [DRY] {rule_id}: {len(fws)} frameworks")
        return

    cur = conn.cursor()
    updated = 0
    for rule_id, fw_list in updates.items():
        cur.execute(
            """UPDATE rule_metadata
               SET compliance_frameworks = %s::jsonb,
                   updated_at = NOW()
               WHERE rule_id = %s AND customer_id IS NULL""",
            (json.dumps(fw_list), rule_id)
        )
        if cur.rowcount:
            updated += 1
    conn.commit()
    cur.close()
    print(f"  Updated {updated} rules in DB")


def run(csps: list, dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    psycopg2.extras.register_default_jsonb(conn)

    grand_total = 0

    for csp in csps:
        print(f"\n{'='*60}")
        print(f"  CSP: {csp.upper()}")
        print(f"{'='*60}")

        mapping = load_mapping(csp)
        if not mapping:
            print(f"  No mapping file found, skipping")
            continue
        print(f"  Loaded {len(mapping)} function mappings")

        db_rules = load_db_rules(conn, csp)
        print(f"  DB has {len(db_rules)} rules for {csp}")

        updates = build_compliance_update(csp, mapping, db_rules, dry_run)
        grand_total += len(updates)

        apply_updates(conn, csp, updates, dry_run)

    conn.close()
    print(f"\n{'='*60}")
    print(f"  GRAND TOTAL: {grand_total} rules updated with compliance frameworks")
    print(f"{'='*60}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--csp', default=None, help='Run for specific CSP only (e.g., aws, gcp)')
    args = parser.parse_args()

    csps = [args.csp] if args.csp else list(CSP_FOLDER.keys())
    run(csps, args.dry_run)
