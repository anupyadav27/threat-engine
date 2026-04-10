"""
Service rule loading, merging, and format normalization.

Handles Phase 2 and Phase 3 YAML rule formats, user rule overlays,
and discovery/check rule merging.

Extracted from service_scanner.py for maintainability.
"""
import json
import logging
import os
import yaml
from typing import Any, Dict

logger = logging.getLogger('compliance-boto3')


def load_enabled_services_with_scope():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]


def _get_check_db_conn():
    """Get connection to threat_engine_check DB (rule_discoveries table)."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=5,
    )


# In-memory cache: service → {rules, updated_at}
_rules_cache: Dict[str, Dict] = {}


def load_service_rules(service_name, provider="aws"):
    """
    Load service rules from rule_discoveries DB table (single source of truth).

    Flow:
      1. Check in-memory cache
      2. If not cached or stale → query rule_discoveries table
      3. Return normalized Phase 2 format rules

    The DB is the ONLY source. YAML files on disk are seed data only.
    """
    cache_key = f"{provider}.{service_name}"

    # Check cache — use if fresh (< 5 min)
    import time
    if cache_key in _rules_cache:
        cached = _rules_cache[cache_key]
        if time.time() - cached.get("_cached_at", 0) < 300:
            return cached["rules"]

    # Load from DB
    try:
        rules = _load_rules_from_db(service_name, provider)
        if rules:
            _rules_cache[cache_key] = {"rules": rules, "_cached_at": time.time()}
            logger.info(f"Loaded rules from DB for {provider}.{service_name}: "
                       f"{len(rules.get('discovery',[]))} discoveries, "
                       f"{len(rules.get('checks',[]))} checks")
            return rules
    except Exception as exc:
        logger.warning(f"Failed to load rules from DB for {service_name}: {exc}")

    # If DB fails, raise — no silent fallback to YAML
    raise RuntimeError(
        f"Cannot load rules for {provider}.{service_name} from rule_discoveries table. "
        f"Ensure the service is seeded in the DB."
    )


def _load_rules_from_db(service_name, provider="aws"):
    """Query rule_discoveries for a service and return Phase 2 format rules."""
    conn = _get_check_db_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT service, discoveries_data, boto3_client_name,
                       filter_rules, updated_at
                FROM rule_discoveries
                WHERE service = %s AND provider = %s AND is_active = true
                LIMIT 1
            """, (service_name, provider))
            row = cur.fetchone()

        if not row:
            return None

        dd = row["discoveries_data"]
        if isinstance(dd, str):
            dd = json.loads(dd)
        if not isinstance(dd, dict):
            return None

        # Normalize to Phase 2 format
        rules = normalize_to_phase2_format(dd)

        # Attach boto3_client_name for the scanner
        rules["_boto3_client_name"] = row.get("boto3_client_name") or service_name
        rules["_filter_rules"] = row.get("filter_rules") or {}
        rules["_updated_at"] = str(row.get("updated_at", ""))

        return rules
    finally:
        conn.close()


def merge_service_rules(base_rules: Dict[str, Any], user_rules: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two Phase-2 service rule documents.
    - Discovery: de-dupe by discovery_id (prefer base definition on conflict)
    - Checks: merge by rule_id (user overrides base on conflict)
    """
    if not base_rules:
        return user_rules or base_rules
    if not user_rules:
        return base_rules

    merged = dict(base_rules)

    # Merge discovery
    base_discovery = merged.get("discovery") or []
    user_discovery = user_rules.get("discovery") or []
    disc_by_id = {d.get("discovery_id"): d for d in base_discovery if isinstance(d, dict) and d.get("discovery_id")}
    for d in user_discovery:
        if not isinstance(d, dict):
            continue
        did = d.get("discovery_id")
        if not did:
            continue
        if did not in disc_by_id:
            disc_by_id[did] = d
        else:
            # Keep base discovery on conflict to avoid user rules changing scan semantics
            pass
    merged["discovery"] = list(disc_by_id.values())

    # Merge checks
    base_checks = merged.get("checks") or []
    user_checks = user_rules.get("checks") or []
    checks_by_id = {c.get("rule_id"): c for c in base_checks if isinstance(c, dict) and c.get("rule_id")}
    base_order = [c.get("rule_id") for c in base_checks if isinstance(c, dict) and c.get("rule_id")]
    for c in user_checks:
        if not isinstance(c, dict):
            continue
        rid = c.get("rule_id")
        if not rid:
            continue
        checks_by_id[rid] = c  # user overrides
        if rid not in base_order:
            base_order.append(rid)
    merged["checks"] = [checks_by_id[rid] for rid in base_order if rid in checks_by_id]

    return merged


def convert_assert_to_conditions(assertion):
    """
    Convert Phase 3 assert to Phase 2 conditions

    Examples:
      assert: item.exists → {var: item.exists, op: exists}
      assert: {item.status: ACTIVE} → {var: item.status, op: equals, value: ACTIVE}
    """
    if isinstance(assertion, str):
        # Simple assertion: assert: item.exists
        return {'var': assertion, 'op': 'exists'}

    elif isinstance(assertion, dict):
        # Dict assertion: assert: {item.status: ACTIVE}
        # Take first key-value pair
        for var, value in assertion.items():
            return {'var': var, 'op': 'equals', 'value': value}

    # Fallback - return as-is
    return assertion


def convert_phase3_to_phase2(rules):
    """
    Convert Phase 3 ultra-simplified format to Phase 2 format

    Phase 3 format:
      service: account
      resources:
        alternate_contacts:
          actions:
          - get_alternate_contact: {AlternateContactType: SECURITY}
      checks:
        contact.configured:
          resource: alternate_contacts
          assert: item.exists

    Phase 2 format:
      service: account
      discovery:
      - discovery_id: aws.account.alternate_contacts
        calls:
        - action: get_alternate_contact
          params: {AlternateContactType: SECURITY}
      checks:
      - rule_id: aws.account.contact.configured
        for_each: aws.account.alternate_contacts
        conditions: {var: item.exists, op: exists}
    """
    service_name = rules.get('service', 'unknown')

    normalized = {
        'version': rules.get('version', '1.0'),
        'provider': rules.get('provider', 'aws'),
        'service': service_name
    }

    # Convert resources to discovery
    if 'resources' in rules:
        discoveries = []

        for resource_name, resource_def in rules['resources'].items():
            discovery_id = f'aws.{service_name}.{resource_name}'

            calls = []
            emit = None

            # Handle different resource definition formats
            if isinstance(resource_def, dict):
                # Extract emit if present at resource level
                if 'emit' in resource_def:
                    emit = resource_def['emit']

                # Handle 'actions' list (multiple actions)
                if 'actions' in resource_def:
                    for action_item in resource_def['actions']:
                        if isinstance(action_item, dict):
                            # {action_name: params_dict}
                            for action_name, params in action_item.items():
                                call = {'action': action_name}
                                if params and isinstance(params, dict):
                                    if 'params' in params:
                                        call['params'] = params['params']
                                    else:
                                        call['params'] = params
                                calls.append(call)
                        elif isinstance(action_item, str):
                            calls.append({'action': action_item})

                # Handle single action format: {action_name: {...}}
                else:
                    for key, value in resource_def.items():
                        if key != 'emit':
                            call = {'action': key}
                            if isinstance(value, dict):
                                if 'params' in value:
                                    call['params'] = value['params']
                                elif value:
                                    call['params'] = value
                                if 'extract' in value:
                                    call['fields'] = value['extract'] if isinstance(value['extract'], list) else [value['extract']]
                                if 'emit' in value:
                                    emit = value['emit']
                            calls.append(call)

            # Create discovery entry
            discovery = {
                'discovery_id': discovery_id,
                'calls': calls
            }

            if emit:
                discovery['emit'] = emit

            discoveries.append(discovery)

        normalized['discovery'] = discoveries

    # Copy discovery section if exists (Phase 2 format)
    elif 'discovery' in rules:
        normalized['discovery'] = rules['discovery']

    # Convert checks
    if 'checks' in rules:
        checks_list = []

        # Phase 3 format: checks is a dict
        if isinstance(rules['checks'], dict):
            for check_name, check_def in rules['checks'].items():
                rule_id = f'aws.{service_name}.{check_name}'

                check_entry = {
                    'rule_id': rule_id
                }

                if 'resource' in check_def:
                    resource_ref = check_def['resource']
                    check_entry['for_each'] = f'aws.{service_name}.{resource_ref}'

                if 'assert' in check_def:
                    check_entry['conditions'] = convert_assert_to_conditions(check_def['assert'])
                elif 'conditions' in check_def:
                    check_entry['conditions'] = check_def['conditions']

                for key in ['params', 'assertion_id']:
                    if key in check_def:
                        check_entry[key] = check_def[key]

                checks_list.append(check_entry)

        # Phase 2 format: checks is a list
        elif isinstance(rules['checks'], list):
            checks_list = rules['checks']

        normalized['checks'] = checks_list

    return normalized


def normalize_to_phase2_format(rules):
    """
    Detect YAML format version and normalize to Phase 2 format for processing

    Supports:
    - Phase 2: discovery/checks (current) - returns as-is
    - Phase 3: resources/checks (ultra-simplified) - converts to Phase 2
    """
    if not rules:
        return rules

    # Detect format version
    if 'resources' in rules:
        logger.debug(f"Detected Phase 3 format, converting to Phase 2")
        return convert_phase3_to_phase2(rules)
    else:
        logger.debug(f"Detected Phase 2 format, using directly")
        return rules
