#!/usr/bin/env python3
"""
Convert Feb 2026 backup check rules → current engine format.

Reads *_rules.yaml from the Feb backup for each CSP, maps discovery_ids,
converts condition format, writes YAML files + inserts into rule_checks
and rule_metadata tables.

Usage:
  python3 scripts/convert_feb_backup_rules.py [--dry-run] [--csp gcp] [--service compute]
"""

import os, glob, yaml, json, re, psycopg2, argparse
from pathlib import Path
from collections import defaultdict

# ── Config ─────────────────────────────────────────────────────────────────
BACKUP_DIR   = "/Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/engine_input"
ENGINE_DIR   = "/Users/apple/Desktop/threat-engine/engines/check"
DB_CONFIG    = {
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port": 5432, "dbname": "threat_engine_check",
    "user": "postgres", "password": "jtv2BkJF8qoFtAKP",
}

CSP_MAP = {
    "gcp":      "engine_configscan_gcp",
    "azure":    "engine_configscan_azure",
    "oci":      "engine_configscan_oci",
    "ibm":      "engine_configscan_ibm",
    "alicloud": "engine_configscan_alicloud",
    "k8s":      "engine_configscan_k8s",
}

# Placeholder conditions to skip (not real checks)
PLACEHOLDER_PATHS = {'lifecycle_state', 'status', 'state'}
PLACEHOLDER_VALUES = {'ACTIVE', 'active', 'RUNNING', 'running'}

# Operator mapping: backup → our engine
OP_MAP = {
    "exists":       "exists",
    "not_exists":   "not_exists",
    "equals":       "equals",
    "not_equals":   "not_equals",
    "contains":     "contains",
    "not_contains": "not_contains",
    "greater_than": "gt",
    "less_than":    "lt",
    "gte":          "gte",
    "lte":          "lte",
    "in":           "in",
    "not_in":       "not_in",
    "starts_with":  "starts_with",
    "ends_with":    "ends_with",
    "regex":        "regex",
    "length_gte":   "length_gte",
}


# ── Load all qualified discovery_ids from rule_discoveries ──────────────────
def load_discovery_index(conn):
    """Returns {provider: {service: [qualified_disc_id, ...]}}"""
    cur = conn.cursor()
    cur.execute("""
        SELECT provider, service, array_agg(DISTINCT disc->>'discovery_id')
        FROM rule_discoveries,
             jsonb_array_elements(discoveries_data->'discovery') disc
        WHERE is_active=true AND disc->>'discovery_id' IS NOT NULL
        GROUP BY provider, service
    """)
    index = defaultdict(lambda: defaultdict(list))
    for provider, service, disc_ids in cur.fetchall():
        index[provider][service] = [d for d in disc_ids if d]
    cur.close()
    return index


def normalize(s):
    """Normalize string for fuzzy matching."""
    return re.sub(r'[^a-z0-9]', '', s.lower())


def normalize_for_each(short_id):
    """Strip list_/get_ prefix and trailing 's', normalize."""
    s = short_id.lower()
    for prefix in ('list_', 'get_', 'list-', 'get-'):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return normalize(s.rstrip('s'))


def match_discovery_id(short_id, provider, service, disc_index):
    """
    Map a short backup discovery_id to our qualified discovery_id.
    Strategy (in order):
      1. Exact match (for already-qualified IDs like azure.xxx.list_by_resource_group)
      2. Action suffix match
      3. Resource name fuzzy match (this service first, then all services)
      4. IBM hyphen-normalized match
      5. Last resort: only 1 discovery_id for this service
    """
    all_provider_ids = [qid for ids in disc_index[provider].values() for qid in ids]
    candidates = disc_index[provider].get(service, [])

    # ── Strategy 1: exact match ──────────────────────────────────────────────
    if short_id in all_provider_ids:
        return short_id

    # ── Strategy 2: already-qualified (starts with provider prefix) ──────────
    if short_id.startswith(f"{provider}."):
        short_parts  = short_id.split('.')
        short_action = short_parts[-1]
        short_svc    = short_parts[1] if len(short_parts) > 1 else ''
        search_pool  = candidates + disc_index[provider].get(short_svc, [])
        for qid in search_pool:
            if qid.endswith(f'.{short_action}') or normalize(short_action) in normalize(qid):
                return qid
        # Broader search
        norm_action = normalize(short_action)
        for qid in all_provider_ids:
            if normalize(qid).endswith(norm_action) or norm_action in normalize(qid):
                return qid
        # Fall through to Strategy 7 (service-level fallback) instead of returning None

    # ── Strategy 3: short id fuzzy matching ─────────────────────────────────
    norm_short = normalize_for_each(short_id)
    if not norm_short:
        return None

    def score_match(qid):
        parts = qid.split('.')
        resource_norm = normalize(parts[-2]) if len(parts) >= 3 else ''
        action_norm   = normalize(parts[-1]) if parts else ''
        full_norm     = normalize(qid)
        if norm_short == resource_norm:                        return 5
        if norm_short == action_norm:                          return 4
        if len(norm_short) > 4 and norm_short in resource_norm: return 3
        if len(norm_short) > 4 and resource_norm in norm_short: return 2
        if len(norm_short) > 4 and norm_short in full_norm:    return 1
        return 0

    # Check this service first
    best, best_score = None, 0
    for qid in candidates:
        s = score_match(qid)
        if s > best_score:
            best, best_score = qid, s
    if best_score >= 3:
        return best

    # Search all services for this provider
    for qid in all_provider_ids:
        s = score_match(qid)
        if s > best_score:
            best, best_score = qid, s
    if best_score >= 3:
        return best

    # ── Strategy 4: IBM hyphen normalization ─────────────────────────────────
    # IBM uses list-accounts, our backup uses accounts → strip s, match
    norm_no_s = norm_short.rstrip('s')
    for qid in all_provider_ids:
        qid_norm = normalize(qid.split('.')[-1])
        qid_no_prefix = re.sub(r'^(list|get)', '', qid_norm)
        qid_no_s = qid_no_prefix.rstrip('s')
        if norm_no_s == qid_no_s or (len(norm_no_s) > 4 and norm_no_s in qid_no_s):
            return qid

    # ── Strategy 5: last resort — single discovery_id for this service ───────
    if len(candidates) == 1:
        return candidates[0]

    # ── Strategy 6: service-prefix stripping (IBM/AliCloud) ──────────────────
    # for_each like "backup_backup_jobs" → strip service prefix → "backup_jobs"
    # or "alicloud.dms.classification_data" → strip provider.service → "classification_data"
    norm_stripped = norm_short
    if service:
        # Strip service name from the start of the for_each
        svc_norm = normalize(service)
        if norm_short.startswith(svc_norm):
            norm_stripped = norm_short[len(svc_norm):].lstrip('_')
        elif norm_short.startswith(normalize(provider) + svc_norm):
            norm_stripped = norm_short[len(normalize(provider)) + len(svc_norm):]
    if norm_stripped and norm_stripped != norm_short and len(norm_stripped) > 3:
        for qid in candidates:
            qid_norm = normalize(qid.split('.')[-1])
            qid_no_prefix = re.sub(r'^(list|get|describe)', '', qid_norm).rstrip('s')
            stripped_no_s = norm_stripped.rstrip('s')
            if stripped_no_s == qid_no_prefix or (len(stripped_no_s) > 4 and stripped_no_s in qid_no_prefix):
                return qid

    # ── Strategy 7: fallback to best list-* in service ───────────────────────
    # When for_each refers to a sub-resource not directly discoverable,
    # map to the primary list operation for the service
    if candidates:
        list_candidates = [q for q in candidates if '.list' in q or '-list' in q or
                          normalize(q.split('.')[-1]).startswith('list')]
        if list_candidates:
            return list_candidates[0]
        return candidates[0]  # last resort: first available

    return None


# ── Condition format conversion ─────────────────────────────────────────────
def convert_fields_to_condition(fields, logic="AND"):
    """Convert backup calls[].fields[] → our conditions dict."""
    if not fields:
        return None

    conditions = []
    for f in fields:
        path     = f.get('path', '')
        operator = f.get('operator', 'exists')
        expected = f.get('expected')

        op = OP_MAP.get(operator, operator)

        # Handle exists/not_exists with expected=false
        if operator == 'exists' and expected is False:
            op = 'not_exists'

        # Build condition entry
        cond = {'var': f'item.{path}', 'op': op}

        # Add value if meaningful
        if op not in ('exists', 'not_exists'):
            if expected is True:
                cond['value'] = 'true'
            elif expected is False:
                cond['value'] = 'false'
            elif expected is not None:
                cond['value'] = str(expected) if not isinstance(expected, (list, dict)) else expected
        elif op == 'exists' and expected is not None and expected is not True:
            cond['value'] = str(expected)

        conditions.append(cond)

    if len(conditions) == 1:
        return conditions[0]
    elif logic == "OR":
        return {'any': conditions}
    else:
        return {'all': conditions}


def normalize_condition_values(cond):
    """Normalize boolean values in conditions to strings."""
    if isinstance(cond, dict):
        if 'value' in cond and isinstance(cond['value'], bool):
            cond = dict(cond)
            cond['value'] = 'true' if cond['value'] else 'false'
        for key in ('all', 'any'):
            if key in cond:
                cond = dict(cond)
                cond[key] = [normalize_condition_values(c) for c in cond[key]]
    return cond


def convert_check_to_conditions(check):
    """Extract conditions from backup check's calls[] section.

    Accepts any action that carries 'fields' — not just the canonical
    eval/identity/get_account_resource — so IBM/GCP/OCI custom actions
    are also processed.
    """
    calls = check.get('calls', [])
    all_fields = []
    logic = check.get('logic', 'AND')

    for call in calls:
        fields = call.get('fields', [])
        if fields:
            all_fields.extend(fields)

    return convert_fields_to_condition(all_fields, logic)


# ── Parse backup rules for a CSP ───────────────────────────────────────────
def is_placeholder_check(check):
    """Return True if all conditions are lifecycle_state/status placeholder checks."""
    calls = check.get('calls', [])
    conditions = check.get('conditions')

    # Azure/AliCloud already use conditions format
    if conditions and not calls:
        return False  # assume real if already in our format

    all_fields = []
    for call in calls:
        all_fields.extend(call.get('fields', []))

    if not all_fields:
        return True  # no fields = nothing to check

    for f in all_fields:
        path = f.get('path', '')
        expected = f.get('expected')
        # Skip if it's a real non-placeholder check
        top_field = path.split('.')[0]
        if top_field not in PLACEHOLDER_PATHS:
            return False
        # lifecycle_state = ACTIVE is placeholder UNLESS it's the only check AND expected is real
        if top_field in PLACEHOLDER_PATHS and expected not in PLACEHOLDER_VALUES and expected not in (True, None):
            return False

    return True  # all fields are placeholder paths


def parse_backup_checks(csp):
    """Returns list of {service, check_id, for_each, check_raw, severity, title}"""
    backup_svc_dir = os.path.join(BACKUP_DIR, CSP_MAP[csp], "input/rule_db/default/services")
    if not os.path.isdir(backup_svc_dir):
        return []

    results = []
    # Match both naming patterns: *_rules.yaml and */rules/*.yaml
    rule_files = (
        glob.glob(f"{backup_svc_dir}/**/*_rules.yaml", recursive=True) +
        glob.glob(f"{backup_svc_dir}/*/rules/*.yaml", recursive=True)
    )

    seen_files = set()
    for rule_file in rule_files:
        if rule_file in seen_files:
            continue
        seen_files.add(rule_file)

        try:
            with open(rule_file) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"  WARN parse error {rule_file}: {e}")
            continue

        if not isinstance(data, dict):
            continue

        # Determine structure type:
        # Type A (flat): has top-level 'checks' key  → Azure, AliCloud, K8s
        # Type B (nested): service_name: {checks: [...]} → GCP, OCI, IBM
        services_data = {}
        if 'checks' in data:
            # Flat: derive service name from file/data
            svc_name = (data.get('service') or data.get('component') or
                        Path(rule_file).stem.replace('_rules', '').replace('.checks', ''))
            services_data[svc_name] = data
        else:
            # Nested under service key
            for key, val in data.items():
                if isinstance(val, dict) and 'checks' in val:
                    services_data[key] = val

        for svc_name, svc_data in services_data.items():
            if not isinstance(svc_data, dict):
                continue
            for check in svc_data.get('checks', []):
                if not isinstance(check, dict):
                    continue
                check_id = check.get('check_id') or check.get('rule_id', '')
                for_each = check.get('for_each', '')
                severity = (check.get('severity') or 'medium').lower()
                title    = check.get('title') or check.get('name') or check_id
                if not check_id or not for_each:
                    continue
                if is_placeholder_check(check):
                    continue
                results.append({
                    'service':   svc_name,
                    'check_id':  check_id,
                    'for_each':  for_each,
                    'check_raw': check,
                    'severity':  severity,
                    'title':     title,
                })

    return results


# ── Parse backup metadata ───────────────────────────────────────────────────
def parse_backup_metadata(csp):
    """Returns {rule_id: metadata_dict}"""
    backup_svc_dir = os.path.join(BACKUP_DIR, CSP_MAP[csp], "input/rule_db/default/services")
    meta = {}
    for mf in glob.glob(f"{backup_svc_dir}/**/metadata/*.yaml", recursive=True):
        try:
            with open(mf) as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        rid = data.get('rule_id') or data.get('check_id') or Path(mf).stem
        if rid:
            meta[rid] = data
    return meta


# ── DB upserts ──────────────────────────────────────────────────────────────
UPSERT_RULE_CHECKS = """
    INSERT INTO rule_checks
        (rule_id, service, provider, check_type, check_config, is_active,
         source, generated_by, version, customer_id, tenant_id, created_at, updated_at)
    VALUES
        (%(rule_id)s, %(service)s, %(provider)s, 'default', %(check_config)s::jsonb,
         true, 'default', 'feb_backup_converter', '1.0',
         NULL, NULL, NOW(), NOW())
    ON CONFLICT (rule_id)
    DO UPDATE SET
        check_config = EXCLUDED.check_config,
        is_active    = true,
        source       = 'default',
        updated_at   = NOW()
"""

UPSERT_RULE_METADATA = """
    INSERT INTO rule_metadata
        (rule_id, service, resource, provider, title, description, rationale,
         remediation, severity, domain, subcategory, rule_class,
         "references", source, metadata_source, generated_by,
         customer_id, tenant_id, created_at, updated_at)
    VALUES
        (%(rule_id)s, %(service)s, %(resource)s, %(provider)s,
         %(title)s, %(description)s, %(rationale)s, %(remediation)s,
         %(severity)s, %(domain)s, %(subcategory)s, 'security',
         %(references)s::jsonb, 'default', 'default', 'feb_backup_converter',
         NULL, NULL, NOW(), NOW())
    ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL
    DO UPDATE SET
        title        = EXCLUDED.title,
        description  = EXCLUDED.description,
        rationale    = EXCLUDED.rationale,
        remediation  = EXCLUDED.remediation,
        severity     = EXCLUDED.severity,
        domain       = EXCLUDED.domain,
        subcategory  = EXCLUDED.subcategory,
        source       = 'default',
        rule_class   = 'security',
        updated_at   = NOW()
"""


def build_metadata_row(rule_id, provider, service, check, backup_meta):
    """Build metadata dict for DB insert."""
    m = backup_meta.get(rule_id, {})
    parts    = rule_id.split('.')
    resource = parts[2] if len(parts) > 2 else service
    severity = (m.get('severity') or check.get('severity') or 'medium').lower()
    if severity not in ('critical','high','medium','low','informational'):
        severity = 'medium'

    refs = m.get('references', [])
    if isinstance(refs, str):
        refs = [refs]

    return {
        'rule_id':     rule_id[:255],
        'service':     service[:100] if service else service,
        'resource':    resource[:100] if resource else resource,
        'provider':    provider,
        'title':       m.get('title') or check.get('title') or check.get('name') or rule_id,
        'description': m.get('description', ''),
        'rationale':   m.get('rationale', ''),
        'remediation': m.get('remediation', ''),
        'severity':    severity,
        'domain':      m.get('domain', 'security_configuration'),
        'subcategory': m.get('subcategory', 'configuration_baseline'),
        'references':  json.dumps(refs),
    }


# ── Main conversion ─────────────────────────────────────────────────────────
def convert_csp(csp, disc_index, conn, dry_run=False, filter_service=None):
    print(f"\n{'='*60}")
    print(f"  CSP: {csp.upper()}")
    print(f"{'='*60}")

    checks   = parse_backup_checks(csp)
    metadata = parse_backup_metadata(csp)

    stats = {'total': 0, 'mapped': 0, 'skipped': 0, 'inserted': 0}
    services_out = defaultdict(list)  # service → list of check dicts for YAML

    for item in checks:
        svc      = item['service']
        if filter_service and svc != filter_service:
            continue

        check_id = item['check_id'][:255]  # rule_id is varchar(255)
        for_each = item['for_each']
        check    = item['check_raw']
        stats['total'] += 1

        # Map for_each to qualified discovery_id
        qualified_id = match_discovery_id(for_each, csp, svc, disc_index)
        if not qualified_id:
            stats['skipped'] += 1
            continue

        # Convert conditions — Azure/AliCloud already have conditions in our format
        if check.get('conditions') and not check.get('calls'):
            conditions = check['conditions']
            # Normalize boolean values to strings
            conditions = normalize_condition_values(conditions)
        else:
            conditions = convert_check_to_conditions(check)
        if not conditions:
            stats['skipped'] += 1
            continue

        stats['mapped'] += 1

        check_config = {'for_each': qualified_id, 'conditions': conditions}

        # Collect for YAML output
        services_out[svc].append({
            'rule_id':    check_id,
            'for_each':   qualified_id,
            'conditions': conditions,
        })

        if not dry_run:
            cur = conn.cursor()
            # Insert rule_checks
            cur.execute(UPSERT_RULE_CHECKS, {
                'rule_id':      check_id,
                'service':      svc,
                'provider':     csp,
                'check_config': json.dumps(check_config),
            })
            # Insert rule_metadata
            meta_row = build_metadata_row(check_id, csp, svc, check, metadata)
            cur.execute(UPSERT_RULE_METADATA, meta_row)
            conn.commit()
            cur.close()
            stats['inserted'] += 1
        else:
            print(f"  [DRY] {check_id}")
            print(f"        for_each: {for_each} → {qualified_id}")
            if len(services_out[svc]) <= 2:  # show first 2 per service
                print(f"        conditions: {json.dumps(conditions)[:120]}")

    # Write YAML files per service
    if not dry_run:
        for svc, svc_checks in services_out.items():
            # Determine engine dir
            engine_svc_dir = os.path.join(
                ENGINE_DIR, f"engine_check_{csp}", "services", svc, "checks", "default"
            )
            os.makedirs(engine_svc_dir, exist_ok=True)
            yaml_path = os.path.join(engine_svc_dir, f"{svc}.checks.yaml")

            yaml_content = {
                'version':  '1.0',
                'provider': csp,
                'service':  svc,
                'checks':   svc_checks,
            }
            with open(yaml_path, 'w') as f:
                yaml.dump(yaml_content, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"\n  Results: total={stats['total']} | mapped={stats['mapped']} "
          f"| skipped(no_disc_id)={stats['skipped']} | inserted={stats['inserted']}")
    print(f"  Services with checks: {len(services_out)}")
    return stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run',  action='store_true')
    parser.add_argument('--csp',      default=None, help='Run for specific CSP only')
    parser.add_argument('--service',  default=None, help='Run for specific service only')
    args = parser.parse_args()

    conn = None if args.dry_run else psycopg2.connect(**DB_CONFIG)

    disc_index = {}
    if not args.dry_run:
        print("Loading discovery index from DB...")
        disc_index = load_discovery_index(conn)
    else:
        # For dry-run, still need discovery index to test mapping
        tmp = psycopg2.connect(**DB_CONFIG)
        disc_index = load_discovery_index(tmp)
        tmp.close()

    csps = [args.csp] if args.csp else list(CSP_MAP.keys())

    total_stats = defaultdict(int)
    for csp in csps:
        stats = convert_csp(csp, disc_index, conn, dry_run=args.dry_run,
                            filter_service=args.service)
        for k, v in stats.items():
            total_stats[k] += v

    print(f"\n{'='*60}")
    print(f"  GRAND TOTAL")
    print(f"  total={total_stats['total']} | mapped={total_stats['mapped']} "
          f"| skipped={total_stats['skipped']} | inserted={total_stats['inserted']}")
    print(f"{'='*60}")

    if conn:
        conn.close()


if __name__ == '__main__':
    main()
