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


def load_service_rules(service_name):
    """
    Load service rules YAML file.
    Handles service name mapping from config names to folder names.
    Each service has its own folder and YAML file.
    The boto3 client mapping (SERVICE_TO_BOTO3_CLIENT) handles SDK client selection.
    """
    base_path = os.path.join(os.path.dirname(__file__), "..", "services")

    # Original logic - load from service folder
    # Try multiple name variations
    possible_names = [
        service_name,  # Exact match
        service_name.replace('_', ''),  # Remove underscores (api_gateway -> apigateway)
    ]

    # Also try with common variations
    if '_' in service_name:
        # Try with different underscore positions
        parts = service_name.split('_')
        possible_names.append(''.join(parts))  # api_gateway -> apigateway
        if len(parts) == 2:
            possible_names.append(parts[0] + parts[1].capitalize())  # api_gateway -> apiGateway

    # Try each possible name
    rules_path = None
    for name in possible_names:
        test_path = os.path.join(base_path, name, "rules", f"{name}.yaml")
        if os.path.exists(test_path):
            rules_path = test_path
            break

    # If still not found, try to find by scanning folders
    if not rules_path:
        service_norm = service_name.replace('_', '').lower()
        if os.path.exists(base_path):
            for folder_name in os.listdir(base_path):
                folder_path = os.path.join(base_path, folder_name)
                if os.path.isdir(folder_path):
                    folder_norm = folder_name.replace('_', '').lower()
                    if folder_norm == service_norm:
                        test_path = os.path.join(folder_path, "rules", f"{folder_name}.yaml")
                        if os.path.exists(test_path):
                            rules_path = test_path
                            break

    if not rules_path:
        raise FileNotFoundError(f"Service rules not found for '{service_name}'. Tried: {possible_names}")

    with open(rules_path) as f:
        rules = yaml.safe_load(f)

    base_rules = normalize_to_phase2_format(rules)

    # Optionally merge user-defined rules (synced into the pod by sidecar)
    # Expected layout: {USER_RULES_DIR}/{service}/{service}.yaml (e.g., /user-rules/s3/s3.yaml)
    user_rules_dir = os.getenv("USER_RULES_DIR")
    if user_rules_dir:
        try:
            user_path = os.path.join(user_rules_dir, service_name, f"{service_name}.yaml")
            if os.path.exists(user_path):
                with open(user_path) as uf:
                    user_rules_raw = yaml.safe_load(uf)
                user_rules = normalize_to_phase2_format(user_rules_raw)
                base_rules = merge_service_rules(base_rules, user_rules)
        except Exception as e:
            logger.warning(f"Failed to load user rules for {service_name}: {e}")

    return base_rules


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
