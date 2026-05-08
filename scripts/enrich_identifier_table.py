#!/usr/bin/env python3
"""
Enrich resource_inventory_identifier table by cross-referencing with rule_discoveries.

For a given CSP:
1. Match canonical identifiers to their primary discovery method
2. Fill root_ops, primary_param (actual AWS field name)
3. Generate new canonical entries for services missing them
4. Mark AWS-managed/noise resources as should_inventory=false
5. Export results as CSV for review before applying

Usage:
    python enrich_identifier_table.py --csp aws --mode analyze   # review only
    python enrich_identifier_table.py --csp aws --mode apply     # update DB
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict

import psycopg2
from psycopg2.extras import RealDictCursor


# ── Noise patterns: AWS-managed/catalog resources that shouldn't be inventoried ──
NOISE_PATTERNS = {
    # AWS catalog/platform data (same for all accounts)
    'instance_type', 'availability_zone', 'bundle', 'blueprint', 'pricing',
    'offering', 'platform_version', 'solution_stack', 'reserved_instance',
    'spot_price', 'savings_plan', 'marketplace', 'account_attribute',
    'account_setting', 'service_quota',
    # System defaults
    'system_schema', 'system_multiregion', 'default_credit',
    # EKS addons (CSP-managed)
    'addon', 'access_policy', 'cluster_version',
    # ECS defaults
    'capacity_provider',
}


def get_connections():
    """Get DB connections from env vars."""
    inv_conn = psycopg2.connect(
        host=os.getenv('INVENTORY_DB_HOST', os.getenv('DB_HOST', 'localhost')),
        port=os.getenv('INVENTORY_DB_PORT', os.getenv('DB_PORT', '5432')),
        database=os.getenv('INVENTORY_DB_NAME', 'threat_engine_inventory'),
        user=os.getenv('INVENTORY_DB_USER', os.getenv('DB_USER', 'postgres')),
        password=os.getenv('INVENTORY_DB_PASSWORD', os.getenv('DB_PASSWORD', '')),
    )
    check_conn = psycopg2.connect(
        host=os.getenv('CHECK_DB_HOST', os.getenv('DB_HOST', 'localhost')),
        port=os.getenv('CHECK_DB_PORT', os.getenv('DB_PORT', '5432')),
        database=os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
        user=os.getenv('CHECK_DB_USER', os.getenv('DB_USER', 'postgres')),
        password=os.getenv('CHECK_DB_PASSWORD', os.getenv('DB_PASSWORD', '')),
    )
    return inv_conn, check_conn


def load_discovery_methods(check_conn, csp):
    """Load all enabled discovery methods for a CSP."""
    cur = check_conn.cursor(cursor_factory=RealDictCursor)
    # Map CSP names between tables (identifier uses 'aws', discoveries uses 'aws')
    provider = csp  # They should match
    cur.execute(
        "SELECT service, discoveries_data FROM rule_discoveries WHERE provider = %s AND is_active = true",
        (provider,)
    )

    methods = []
    for row in cur.fetchall():
        svc = row['service']
        data = row['discoveries_data']
        if isinstance(data, str):
            data = json.loads(data)

        for op in data.get('discovery', []):
            if not op.get('enabled', True):
                continue
            calls = op.get('calls', [])
            action = calls[0].get('action', '') if calls else ''
            emit = op.get('emit', {})
            items_for = emit.get('items_for', '').replace('{{ ', '').replace(' }}', '')
            item_template = emit.get('item', {})
            emit_fields = set(item_template.keys()) if isinstance(item_template, dict) else set()
            is_dep = bool(op.get('for_each'))

            # Extract resource noun from items_for path
            resource_noun = ''
            if items_for:
                parts = items_for.split('.')
                resource_noun = parts[-1].rstrip('[]')

            methods.append({
                'service': svc,
                'discovery_id': op['discovery_id'],
                'action': action,
                'items_for': items_for,
                'resource_noun': resource_noun,
                'emit_fields': emit_fields,
                'emit_count': len(emit_fields),
                'is_dep': is_dep,
            })

    return methods


def load_identifiers(inv_conn, csp):
    """Load all identifier entries for a CSP."""
    cur = inv_conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id, service, resource_type, identifier_pattern, has_arn,
               can_inventory_from_roots, should_inventory, root_ops, primary_param,
               category, scope, is_container, diagram_priority, managed_by
        FROM resource_inventory_identifier
        WHERE csp = %s
    """, (csp,))

    entries = []
    for r in cur.fetchall():
        pattern = r['identifier_pattern'] or ''

        # Parse id_field from pattern: ${FieldName} at the end
        fields = re.findall(r'\$\{(\w+)\}', pattern)
        id_field = None
        for f in reversed(fields):
            if f not in ('Partition', 'Region', 'Account'):
                id_field = f
                break

        # Parse ARN resource type from pattern
        arn_resource_type = None
        if pattern:
            parts = pattern.split(':')
            if len(parts) >= 6:
                rpart = ':'.join(parts[5:])
                arn_resource_type = rpart.split('/')[0].split('${')[0].rstrip('/')

        entries.append({
            **dict(r),
            'id_field': id_field,
            'arn_resource_type': arn_resource_type,
            'is_canonical': r['resource_type'].startswith('_canonical_'),
        })

    return entries


def match_identifier_to_discovery(identifier, methods):
    """Find the best discovery method for an identifier entry using scoring."""
    svc = identifier['service']
    id_field = identifier['id_field']
    arn_rt = identifier['arn_resource_type'] or ''

    svc_methods = [m for m in methods if m['service'] == svc and not m['is_dep']]

    best_match = None
    best_score = 0

    for method in svc_methods:
        score = 0
        noun = method['resource_noun']

        # Must have the id_field in emit
        if id_field and id_field in method['emit_fields']:
            score += 10
        else:
            continue

        # Resource noun matches ARN resource type
        noun_lower = noun.lower().rstrip('s').rstrip('e')
        arn_lower = arn_rt.lower().replace('-', '_').replace(' ', '_')
        if noun_lower and arn_lower:
            if noun_lower == arn_lower:
                score += 50
            elif noun_lower in arn_lower or arn_lower in noun_lower:
                score += 30
            elif arn_lower.replace('_', '') in noun_lower.replace('_', ''):
                score += 20

        # Action name contains resource type
        action_lower = method['action'].lower()
        if arn_lower and arn_lower in action_lower:
            score += 15

        # More emit fields = more complete data
        score += min(method['emit_count'], 20)

        # Prefer describe over list (describe has full data)
        if action_lower.startswith('describe_'):
            score += 5
        elif action_lower.startswith('get_'):
            score += 3

        if score > best_score:
            best_score = score
            best_match = method

    return best_match, best_score


def is_noise_resource(identifier, method=None):
    """Check if a resource is AWS-managed noise that shouldn't be inventoried."""
    rt = identifier['resource_type'].lower()
    action = (method['action'] if method else '').lower()

    for pattern in NOISE_PATTERNS:
        if pattern in rt or pattern in action:
            return True

    return False


def analyze(csp):
    """Analyze and generate enrichment recommendations."""
    inv_conn, check_conn = get_connections()

    methods = load_discovery_methods(check_conn, csp)
    identifiers = load_identifiers(inv_conn, csp)

    print(f"\n=== {csp.upper()} ENRICHMENT ANALYSIS ===")
    print(f"Identifier entries: {len(identifiers)}")
    print(f"Discovery methods: {len(methods)}")

    canonicals = [i for i in identifiers if i['is_canonical'] and i['should_inventory'] and i['has_arn']]
    print(f"Canonical entries: {len(canonicals)}")

    results = []

    # 1. Match existing canonical entries to discovery methods
    for canon in canonicals:
        match, score = match_identifier_to_discovery(canon, methods)
        rt = canon['resource_type'].replace('_canonical_', '')
        noise = is_noise_resource(canon, match)

        if noise:
            status = 'NOISE'
        elif match and score >= 30:
            status = 'ENRICH'
        elif match:
            status = 'LOW_CONFIDENCE'
        else:
            status = 'NO_MATCH'

        results.append({
            'action': status,
            'service': canon['service'],
            'resource': rt,
            'id_field': canon['id_field'],
            'arn_type': canon['arn_resource_type'],
            'pattern': canon['identifier_pattern'],
            'discovery_id': match['discovery_id'] if match else '',
            'discovery_action': match['action'] if match else '',
            'score': score,
            'emit_count': match['emit_count'] if match else 0,
            'identifier_id': canon['id'],
        })

    # 2. Find services with discoveries but no canonical identifier
    id_services = set(i['service'] for i in identifiers)
    disc_services = set(m['service'] for m in methods)

    for svc in sorted(disc_services - id_services):
        svc_methods = [m for m in methods if m['service'] == svc and not m['is_dep']]
        if not svc_methods:
            continue
        # Pick the method with most emit fields (most complete data)
        best = max(svc_methods, key=lambda m: m['emit_count'])
        if best['emit_count'] > 0:
            results.append({
                'action': 'NEW_SERVICE',
                'service': svc,
                'resource': best['resource_noun'] or 'resource',
                'id_field': '',
                'arn_type': '',
                'pattern': '',
                'discovery_id': best['discovery_id'],
                'discovery_action': best['action'],
                'score': 0,
                'emit_count': best['emit_count'],
                'identifier_id': None,
            })

    # 3. Check non-canonical entries that should be promoted
    non_canonical_inventoriable = [
        i for i in identifiers
        if not i['is_canonical'] and i['should_inventory'] and i['has_arn']
        and i['can_inventory_from_roots']
    ]

    # Group by service + arn_resource_type to find unique resources without canonical
    existing_canonical_keys = set(
        f"{c['service']}.{c['arn_resource_type']}"
        for c in canonicals if c['arn_resource_type']
    )

    promote_candidates = defaultdict(list)
    for entry in non_canonical_inventoriable:
        key = f"{entry['service']}.{entry['arn_resource_type']}"
        if key not in existing_canonical_keys and entry['arn_resource_type']:
            promote_candidates[key].append(entry)

    for key, entries in promote_candidates.items():
        # Pick the one with root_ops if available
        best = entries[0]
        for e in entries:
            if e['root_ops'] and e['root_ops'] != [] and e['root_ops'] != '[]':
                best = e
                break

        match, score = match_identifier_to_discovery(best, methods)
        noise = is_noise_resource(best, match)

        if noise:
            continue

        results.append({
            'action': 'PROMOTE',
            'service': best['service'],
            'resource': best['arn_resource_type'],
            'id_field': best['id_field'],
            'arn_type': best['arn_resource_type'],
            'pattern': best['identifier_pattern'],
            'discovery_id': match['discovery_id'] if match else '',
            'discovery_action': match['action'] if match else '',
            'score': score,
            'emit_count': match['emit_count'] if match else 0,
            'identifier_id': best['id'],
        })

    # Summary
    by_action = defaultdict(int)
    for r in results:
        by_action[r['action']] += 1

    print(f"\n=== RESULTS ===")
    for action, count in sorted(by_action.items()):
        print(f"  {action}: {count}")
    print(f"  TOTAL: {len(results)}")

    # Export CSV
    csv_path = f'/tmp/{csp}_identifier_enrichment.csv'
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'action', 'service', 'resource', 'id_field', 'arn_type', 'pattern',
            'discovery_id', 'discovery_action', 'score', 'emit_count', 'identifier_id'
        ])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCSV exported: {csv_path}")

    # Print details
    print(f"\n=== ENRICH (update root_ops + primary_param) ===")
    for r in sorted(results, key=lambda x: x['score'], reverse=True):
        if r['action'] == 'ENRICH':
            print(f"  {r['service']:15s} {r['resource']:25s} id={r['id_field']:20s} → {r['discovery_action']:35s} score={r['score']}")

    print(f"\n=== NOISE (mark should_inventory=false) ===")
    for r in results:
        if r['action'] == 'NOISE':
            print(f"  {r['service']:15s} {r['resource']:25s}")

    print(f"\n=== NO_MATCH (need manual review) ===")
    for r in results:
        if r['action'] == 'NO_MATCH':
            print(f"  {r['service']:15s} {r['resource']:25s} id_field={r['id_field']}")

    print(f"\n=== PROMOTE (create canonical from non-canonical) ===")
    for r in sorted(results, key=lambda x: x['score'], reverse=True):
        if r['action'] == 'PROMOTE':
            print(f"  {r['service']:15s} {r['resource']:25s} → {r['discovery_action']:35s} score={r['score']}")

    print(f"\n=== NEW_SERVICE (first 20, no identifier entry at all) ===")
    for r in [r for r in results if r['action'] == 'NEW_SERVICE'][:20]:
        print(f"  {r['service']:15s} → {r['discovery_action']:35s} fields={r['emit_count']}")

    inv_conn.close()
    check_conn.close()
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enrich identifier table')
    parser.add_argument('--csp', default='aws', help='CSP to process')
    parser.add_argument('--mode', default='analyze', choices=['analyze', 'apply'])
    args = parser.parse_args()

    results = analyze(args.csp)

    if args.mode == 'apply':
        print("\n⚠️  Apply mode not yet implemented. Review the CSV first.")
        print("    Once reviewed, run with --mode apply to update the DB.")
