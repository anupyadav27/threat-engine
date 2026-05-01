#!/usr/bin/env python3
"""
Load OCI check rules from S3-downloaded YAML files into rule_checks and rule_metadata tables.
Source: /Users/apple/Desktop/threat-engine-s3-input/engine_check_oci/

The YAML files have short discovery_ids (e.g. 'list_buckets') that must be
qualified to the full DB form (e.g. 'oci.object_storage.list_buckets').

Usage:
  python3 scripts/load_oci_s3_rules.py [--dry-run] [--service compute]
"""

import os, sys, yaml, json, psycopg2, argparse, re
from pathlib import Path

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

S3_BASE = Path("/Users/apple/Desktop/threat-engine-s3-input/engine_check_oci/input/rule_db/default/services")

DOMAIN_MAP = {
    'compute':            'compute_and_workload_security',
    'container_engine':   'compute_and_workload_security',
    'container_instances':'compute_and_workload_security',
    'database':           'data_security',
    'mysql':              'data_security',
    'nosql':              'data_security',
    'data_safe':          'data_security',
    'object_storage':     'data_security',
    'file_storage':       'data_security',
    'block_storage':      'data_security',
    'vault':              'data_security',
    'key_management':     'data_security',
    'identity':           'identity_and_access_management',
    'iam':                'identity_and_access_management',
    'virtual_network':    'network_security',
    'network_firewall':   'network_security',
    'load_balancer':      'network_security',
    'dns':                'network_security',
    'waf':                'network_security',
    'logging':            'security_monitoring',
    'audit':              'security_monitoring',
    'cloud_guard':        'security_monitoring',
    'monitoring':         'security_monitoring',
    'events':             'security_monitoring',
}


def convert_fields_to_conditions(fields: list, logic: str = 'AND') -> dict:
    """Convert YAML fields list to DB conditions structure."""
    if not fields:
        return {}

    if len(fields) == 1:
        f = fields[0]
        cond = {'op': f.get('operator', 'equals'), 'var': f'item.{f["path"]}'}
        if 'expected' in f:
            cond['value'] = f['expected']
        return cond

    conditions = []
    for f in fields:
        cond = {'op': f.get('operator', 'equals'), 'var': f'item.{f["path"]}'}
        if 'expected' in f:
            cond['value'] = f['expected']
        conditions.append(cond)

    return {'op': logic.lower(), 'conditions': conditions}


def build_check_config(check: dict, qualified_for_each: str) -> dict:
    """Build check_config JSONB from check definition."""
    calls = check.get('calls', [])
    all_fields = []
    logic = check.get('logic', 'AND')

    for call in calls:
        fields = call.get('fields', [])
        if fields:
            all_fields.extend(fields)

    conditions = convert_fields_to_conditions(all_fields, logic)
    return {
        'for_each': qualified_for_each,
        'conditions': conditions,
    }


def qualify_for_each(short_id: str, service: str, service_discovery_map: dict) -> str:
    """
    Map short discovery_id (e.g. 'list_buckets') to qualified form
    (e.g. 'oci.object_storage.list_buckets').
    """
    if not short_id:
        return None

    # Already qualified
    if short_id.startswith('oci.'):
        return short_id

    # Check in this service's discovery map
    if short_id in service_discovery_map:
        return service_discovery_map[short_id]

    return None


def load_service_discovery_from_db(cur, service: str) -> dict:
    """Load discovery_ids from rule_discoveries for a service, return {short_id: qualified_id}."""
    cur.execute("""
        SELECT d->>'discovery_id' as disc_id
        FROM rule_discoveries,
             jsonb_array_elements(discoveries_data->'discovery') d
        WHERE service = %s AND provider = 'oci' AND customer_id IS NULL
    """, (service,))

    mapping = {}
    for row in cur.fetchall():
        qualified = row[0]
        if qualified:
            # short = last segment after dot
            short = qualified.split('.')[-1]
            mapping[short] = qualified
            # Also map without 'oci.service.' prefix
            parts = qualified.split('.')
            if len(parts) > 2:
                mapping['.'.join(parts[2:])] = qualified  # e.g. 'get_unprocessed_data_bucket'

    return mapping


def parse_service_yaml(yaml_path: Path, service: str) -> tuple:
    """Parse a service YAML and return (discoveries, checks)."""
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    if not data:
        return [], []

    # Top-level key is the service name
    svc_key = list(data.keys())[0]
    svc_data = data[svc_key]

    discoveries = svc_data.get('discovery', [])
    checks = svc_data.get('checks', [])
    return discoveries, checks


def build_local_discovery_map(discoveries: list, service: str) -> dict:
    """Build {short_id: qualified_id} from service YAML's discovery section."""
    mapping = {}
    for d in discoveries:
        disc_id = d.get('discovery_id', '')
        if disc_id:
            mapping[disc_id] = f'oci.{service}.{disc_id}'
    return mapping


def load_metadata_yaml(meta_dir: Path, check_id: str) -> dict:
    """Load metadata YAML file for a check, return dict or {}."""
    yaml_path = meta_dir / f'{check_id}.yaml'
    if yaml_path.exists():
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        return data or {}
    return {}


def run(services_filter: list, dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    services = sorted([d.name for d in S3_BASE.iterdir() if d.is_dir()])
    if services_filter:
        services = [s for s in services if s in services_filter]

    print(f"Processing {len(services)} OCI services...")

    total_checks = 0
    total_meta = 0
    placeholder_updated = 0
    errors = []

    for service in services:
        svc_dir = S3_BASE / service
        rules_file = svc_dir / 'rules' / f'{service}.yaml'
        meta_dir = svc_dir / 'metadata'

        if not rules_file.exists():
            print(f"  [{service}] No rules file, skipping")
            continue

        discoveries, checks = parse_service_yaml(rules_file, service)

        if not checks:
            print(f"  [{service}] No checks, skipping")
            continue

        # Build discovery mapping: short_id → qualified_id
        # First from YAML, then supplement with DB
        local_map = build_local_discovery_map(discoveries, service)
        db_map = load_service_discovery_from_db(cur, service)

        # Merge: local YAML takes priority
        disc_map = {**db_map, **local_map}

        svc_checks = 0
        svc_meta = 0
        svc_placeholder = 0

        for check in checks:
            check_id = check.get('check_id', '')
            if not check_id:
                continue

            # Qualify for_each
            short_fe = check.get('for_each', '')
            qualified_fe = qualify_for_each(short_fe, service, disc_map)

            if not qualified_fe and short_fe:
                # Try fallback: look for any list_* in this service
                list_cands = [v for k, v in disc_map.items() if k.startswith('list_')]
                qualified_fe = list_cands[0] if list_cands else f'oci.{service}.{short_fe}'
            elif not qualified_fe:
                qualified_fe = f'oci.{service}.list_{service}s'

            # Build check_config
            check_config = build_check_config(check, qualified_fe)

            # Check if it's a placeholder
            calls = check.get('calls', [])
            is_placeholder = False
            for call in calls:
                for f in call.get('fields', []):
                    if 'active state' in f.get('description', '').lower():
                        is_placeholder = True
                        break

            if dry_run:
                if svc_checks < 2:
                    print(f"    [DRY] {check_id}")
                    print(f"          for_each: {short_fe} → {qualified_fe}")
                    print(f"          placeholder: {is_placeholder}")
                svc_checks += 1
                if is_placeholder:
                    svc_placeholder += 1
                continue

            # Upsert rule_checks
            cur.execute("""
                INSERT INTO rule_checks (rule_id, service, provider, check_config, source, generated_by, created_at, updated_at)
                VALUES (%s, %s, 'oci', %s::jsonb, 'oci_s3', 'oci_s3_loader', NOW(), NOW())
                ON CONFLICT (rule_id) DO UPDATE SET
                    check_config = EXCLUDED.check_config,
                    service = EXCLUDED.service,
                    updated_at = NOW()
            """, (check_id, service, json.dumps(check_config)))
            svc_checks += 1
            if is_placeholder:
                svc_placeholder += 1

            # Load metadata YAML and upsert rule_metadata
            meta = load_metadata_yaml(meta_dir, check_id)
            if meta:
                domain = meta.get('domain') or DOMAIN_MAP.get(service, 'cloud_security')
                cur.execute("""
                    INSERT INTO rule_metadata (
                        rule_id, provider, service, title, description, severity,
                        domain, subcategory, rationale, remediation, "references",
                        generated_by, created_at, updated_at
                    ) VALUES (
                        %(rule_id)s, 'oci', %(service)s, %(title)s, %(description)s,
                        %(severity)s, %(domain)s, %(subcategory)s, %(rationale)s,
                        %(remediation)s, %(references)s::jsonb, 'oci_s3_loader', NOW(), NOW()
                    )
                    ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL
                    DO UPDATE SET
                        title = COALESCE(NULLIF(rule_metadata.title,''), EXCLUDED.title),
                        description = COALESCE(NULLIF(rule_metadata.description,''), EXCLUDED.description),
                        severity = COALESCE(NULLIF(rule_metadata.severity,''), EXCLUDED.severity),
                        domain = COALESCE(NULLIF(rule_metadata.domain,''), EXCLUDED.domain),
                        subcategory = COALESCE(NULLIF(rule_metadata.subcategory,''), EXCLUDED.subcategory),
                        rationale = COALESCE(NULLIF(rule_metadata.rationale,''), EXCLUDED.rationale),
                        remediation = COALESCE(NULLIF(rule_metadata.remediation,''), EXCLUDED.remediation),
                        "references" = CASE
                            WHEN rule_metadata."references" IS NULL OR rule_metadata."references"::text IN ('null','[]')
                            THEN EXCLUDED."references"
                            ELSE rule_metadata."references"
                        END,
                        updated_at = NOW()
                """, {
                    'rule_id':     check_id[:255],
                    'service':     meta.get('service', service)[:100],
                    'title':       meta.get('title', check_id)[:500] if meta.get('title') else check_id[:500],
                    'description': meta.get('description', ''),
                    'severity':    meta.get('severity', 'medium'),
                    'domain':      domain,
                    'subcategory': meta.get('subcategory', ''),
                    'rationale':   meta.get('rationale', ''),
                    'remediation': meta.get('description', ''),
                    'references':  json.dumps(meta.get('references', [])),
                })
                svc_meta += 1

        if not dry_run:
            conn.commit()

        print(f"  [{service}] {svc_checks} checks ({svc_placeholder} placeholder), {svc_meta} metadata updated")
        total_checks += svc_checks
        total_meta += svc_meta
        placeholder_updated += svc_placeholder

    print(f"\nTotal: {total_checks} checks upserted, {total_meta} metadata updated")
    print(f"Placeholder checks: {placeholder_updated}")

    cur.close()
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--service', default=None, help='Comma-separated service list')
    args = parser.parse_args()

    services_filter = [s.strip() for s in args.service.split(',')] if args.service else []
    run(services_filter, args.dry_run)
