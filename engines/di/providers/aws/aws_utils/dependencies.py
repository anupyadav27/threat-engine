"""
Dependency graph construction, inventory enrichment, and check execution.

Handles multi-level discovery dependencies, topological ordering,
ARN-based resource matching, and individual check evaluation.

Extracted from service_scanner.py for maintainability.
"""
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .extraction import (
    extract_value,
    extract_checked_fields,
    extract_resource_identifier,
)
from .conditions import evaluate_condition, resolve_template

logger = logging.getLogger('compliance-boto3')


def _build_dependency_graph(discoveries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build complete dependency graph with multi-level support.

    Returns:
    {
        'independent': [disc1, disc2, ...],  # Discoveries with no for_each
        'dependent_groups': {
            'source_disc_id': [dependent1, dependent2, ...],  # Direct dependents only (backward compat)
            ...
        },
        'dependency_tree': {
            'independent_id': {
                'direct_dependents': [dep1, dep2, ...],
                'all_dependents': [dep1, dep2, dep3, ...],  # Direct + indirect
                'enrichment_order': [deepest_dep, ..., dep1, dep2]  # Topological order
            }
        },
        'dependency_map': {
            'discovery_id': 'depends_on_id'  # Maps each discovery to what it depends on
        }
    }
    """
    independent = []
    dependent_by_source = {}
    dependency_map = {}
    discovery_by_id = {}

    # First pass: identify all discoveries and their dependencies
    for disc in discoveries:
        discovery_id = disc.get('discovery_id')
        if not discovery_id:
            continue

        discovery_by_id[discovery_id] = disc

        # Check for for_each at discovery level or call level
        for_each = disc.get('for_each')
        if not for_each:
            for call in disc.get('calls', []):
                for_each = call.get('for_each')
                if for_each:
                    break

        if not for_each:
            independent.append(disc)
            dependency_map[discovery_id] = None
        else:
            items_ref = for_each.replace('{{ ', '').replace(' }}', '')
            dependency_map[discovery_id] = items_ref

            if items_ref not in dependent_by_source:
                dependent_by_source[items_ref] = []
            dependent_by_source[items_ref].append(disc)

    # Build complete dependency tree for each independent discovery
    dependency_tree = {}

    def _resolve_dependency_chain(discovery_id: str, visited: set = None) -> List[str]:
        """
        Recursively find all dependents (direct + indirect) for a discovery.
        Returns list ordered from deepest to shallowest (topological order).
        """
        if visited is None:
            visited = set()

        if discovery_id in visited:
            logger.warning(f"Circular dependency detected involving {discovery_id}")
            return []

        visited.add(discovery_id)
        all_dependents = []

        direct_dependents = dependent_by_source.get(discovery_id, [])

        for dep_disc in direct_dependents:
            dep_id = dep_disc.get('discovery_id')
            if not dep_id:
                continue

            nested_dependents = _resolve_dependency_chain(dep_id, visited.copy())

            all_dependents.extend(nested_dependents)

            if dep_id not in all_dependents:
                all_dependents.append(dep_id)

        return all_dependents

    for indep_disc in independent:
        indep_id = indep_disc.get('discovery_id')
        if not indep_id:
            continue

        direct_dependents = [d.get('discovery_id') for d in dependent_by_source.get(indep_id, [])]
        all_dependents = _resolve_dependency_chain(indep_id)

        dependency_tree[indep_id] = {
            'direct_dependents': direct_dependents,
            'all_dependents': all_dependents,
            'enrichment_order': all_dependents
        }

    return {
        'independent': independent,
        'dependent_groups': dependent_by_source,
        'dependency_tree': dependency_tree,
        'dependency_map': dependency_map,
        'discovery_by_id': discovery_by_id
    }


def _enrich_inventory_with_dependent_discoveries(
    discovery_results: Dict[str, List[Dict]],
    service_rules: Dict[str, Any],
    dependency_graph: Dict[str, Any]
) -> Dict[str, List[Dict]]:
    """
    Enrich inventory by merging dependent discovery results into independent discovery items.
    Supports multi-level dependencies (dependent -> dependent -> independent).

    Strategy:
    1. Independent discoveries create base inventory items with standard template fields
    2. Dependent discoveries enrich these items by adding their fields
    3. Multi-level: Dependent discoveries can enrich other dependent discoveries first
    4. Enrichment happens in topological order (deepest -> independent)
    5. Preserve standard fields (resource_arn, resource_id, resource_type, name, tags)
    6. Add dependent fields as additional top-level fields (enrichment)

    This function does NOT modify checks or scan collection - only enriches inventory data.
    """
    from common.utils.reporting_manager import is_cspm_inventory_resource

    enriched_results = discovery_results.copy()
    dependency_tree = dependency_graph.get('dependency_tree', {})
    dependent_groups = dependency_graph.get('dependent_groups', {})
    discovery_by_id = dependency_graph.get('discovery_by_id', {})

    PROTECTED_FIELDS = {
        'resource_arn', 'resource_id', 'resource_type', 'resource_name',
        'resource_uid', 'name', 'tags', 'Name'
    }

    def _merge_dependent_data(source_items: List[Dict], target_items: List[Dict],
                              dependent_id: str, target_id: str) -> int:
        """
        Merge dependent discovery data into target items using ARN-based matching.
        Returns number of items successfully enriched.
        """
        if not source_items or not target_items:
            return 0

        matched_count = 0
        for target_item in target_items:
            if matched_count < 2:
                target_arn = target_item.get('resource_arn')
                if target_arn:
                    logger.info(f"[MATCH-DEBUG] {dependent_id} -> {target_id}: Target item has resource_arn: {target_arn[:80]}")
                else:
                    logger.warning(f"[MATCH-DEBUG] {dependent_id} -> {target_id}: Target item has NO resource_arn! Available keys: {list(target_item.keys())[:15]}")

            target_arn = target_item.get('resource_arn')
            if not target_arn:
                target_arn_str = 'N/A'
                logger.debug(f"No match for item ARN: {target_arn_str[:80]} (no ARN in target)")
                continue

            matching_sources = []
            for source_item in source_items:
                source_arn = source_item.get('resource_arn')
                if source_arn and source_arn == target_arn:
                    matching_sources.append(source_item)

            if matching_sources:
                if len(matching_sources) == 1:
                    source_item = matching_sources[0]
                    for key, value in source_item.items():
                        if key not in PROTECTED_FIELDS and key not in target_item:
                            target_item[key] = value
                else:
                    for i, source_item in enumerate(matching_sources):
                        for key, value in source_item.items():
                            if key not in PROTECTED_FIELDS:
                                if i == 0:
                                    if key not in target_item:
                                        target_item[key] = value
                                else:
                                    list_key = f"_{dependent_id.split('.')[-1]}_items"
                                    if list_key not in target_item:
                                        target_item[list_key] = []
                                    target_item[list_key].append(source_item)
                                    break

                matched_count += 1

        return matched_count

    # Process enrichment in topological order
    for indep_id, tree_info in dependency_tree.items():
        enrichment_order = tree_info.get('enrichment_order', [])

        if not enrichment_order:
            continue

        for dep_id in enrichment_order:
            source_items = enriched_results.get(dep_id, [])
            if not source_items:
                continue

            dep_config = discovery_by_id.get(dep_id, {})
            for_each = dep_config.get('for_each')
            if not for_each:
                for call in dep_config.get('calls', []):
                    for_each = call.get('for_each')
                    if for_each:
                        break

            if not for_each:
                continue

            target_id = for_each.replace('{{ ', '').replace(' }}', '')
            target_items = enriched_results.get(target_id, [])

            if not target_items:
                continue

            matched = _merge_dependent_data(source_items, target_items, dep_id, target_id)
            logger.info(f"[ENRICH] {dep_id} -> {target_id}: Matched {matched}/{len(target_items)} items")

    # Log final enrichment summary
    for disc_id, items in enriched_results.items():
        if not items:
            continue
        sample = items[0] if items else {}
        if any(k not in {'resource_arn', 'resource_id', 'resource_type', 'resource_name', 'resource_uid', 'name', 'tags', 'Name', '_discovery_id'} for k in sample.keys()):
            if logger.isEnabledFor(logging.INFO):
                logger.info(f"[ENRICH-FINAL] {disc_id}: {len(items)} items")
                logger.info(f"[ENRICH-FINAL] Sample item keys: {list(sample.keys())[:20]}")
            break
        else:
            if logger.isEnabledFor(logging.WARNING):
                logger.warning(f"[ENRICH-FINAL] {disc_id} has NO enriched fields! Item keys: {list(sample.keys())[:20]}")
            break

    return enriched_results


def _resolve_check_dependencies(
    check_for_each: str,
    service_rules: Dict[str, Any],
    discovery_results: Dict[str, List[Dict]]
) -> Tuple[str, Optional[str]]:
    """
    Resolve check's for_each back to independent discovery by following dependency chain.
    Loops until we find an independent discovery (one with no for_each).

    Args:
        check_for_each: Check's for_each value (e.g., 'aws.s3.get_bucket_versioning')
        service_rules: Loaded service rules YAML
        discovery_results: Dictionary of discovery_id -> emitted items

    Returns:
        (independent_discovery_id, dependent_discovery_id)
    """
    visited = set()
    current = check_for_each

    while current:
        if current in visited:
            logger.warning(f"Circular dependency detected in check for_each: {check_for_each}")
            return (None, None)
        visited.add(current)

        discovery_config = None
        for disc in service_rules.get('discovery', []):
            if disc.get('discovery_id') == current:
                discovery_config = disc
                break

        if not discovery_config:
            if current in discovery_results and discovery_results[current]:
                return (current, None)
            return (None, None)

        for_each = discovery_config.get('for_each')
        if not for_each:
            for call in discovery_config.get('calls', []):
                for_each = call.get('for_each')
                if for_each:
                    break

        if not for_each:
            if current == check_for_each:
                return (current, None)
            else:
                return (current, check_for_each)

        if isinstance(for_each, dict):
            current = for_each.get('discovery')
        else:
            current = str(for_each)

    return (None, None)


def _match_items(
    primary_item: Dict,
    dependent_items: List[Dict],
    match_keys: List[str] = None  # Deprecated - now uses ARN only
) -> Optional[Dict]:
    """
    Match a primary item with a corresponding item in dependent discovery using ARN.

    ARN-based matching is universal across all AWS services and eliminates the need
    for service-specific matching keys.
    """
    primary_arn = primary_item.get('resource_arn')
    if not primary_arn:
        logger.debug(f"No resource_arn in primary item, available keys: {list(primary_item.keys())[:10]}")
        return None

    for dep_item in dependent_items:
        dep_arn = dep_item.get('resource_arn')
        if dep_arn and dep_arn == primary_arn:
            return dep_item

    return None


def _run_single_check(
    check: Dict[str, Any],
    service_name: str,
    region: str,
    account_id: Optional[str],
    discovery_results: Dict[str, List[Dict]],
    service_rules: Dict[str, Any],
    primary_items: Optional[List[Dict]] = None
) -> List[Dict[str, Any]]:
    """
    Run a single check - can be executed in parallel with other checks.

    All checks share the same discovery_results (reference, not copy).
    Checks are independent - they only depend on discoveries, not each other.
    """
    check_id = check['rule_id']
    title = check.get('title', '')
    severity = check.get('severity', 'medium')
    assertion_id = check.get('assertion_id', '')
    for_each = check.get('for_each')
    params = check.get('params', {})
    conditions = check.get('conditions', {})

    is_account_level_check = '.account.' in check_id or check_id.endswith('.account')

    # Get items to check - resolve dependencies to independent discovery
    if for_each and isinstance(for_each, dict):
        discovery_id = for_each.get('discovery')
        if discovery_id:
            independent_disc_id, dependent_disc_id = _resolve_check_dependencies(
                discovery_id, service_rules, discovery_results
            )
        else:
            independent_disc_id, dependent_disc_id = None, None
    elif for_each:
        independent_disc_id, dependent_disc_id = _resolve_check_dependencies(
            for_each, service_rules, discovery_results
        )
    else:
        independent_disc_id, dependent_disc_id = None, None

    # Build items list based on dependency resolution
    if independent_disc_id:
        primary_items_from_independent = discovery_results.get(independent_disc_id, [])

        if dependent_disc_id:
            dependent_items = discovery_results.get(dependent_disc_id, [])
            items = []

            for primary_item in primary_items_from_independent:
                matched_item = _match_items(primary_item, dependent_items)
                if matched_item:
                    combined_item = {**primary_item, **matched_item}
                    items.append(combined_item)
                else:
                    items.append(primary_item)
        else:
            items = primary_items_from_independent
    else:
        if for_each and isinstance(for_each, dict):
            discovery_id = for_each.get('discovery')
            if discovery_id:
                items = discovery_results.get(discovery_id, [])
            elif discovery_results:
                first_discovery_id = list(discovery_results.keys())[0]
                items = discovery_results.get(first_discovery_id, [])
            else:
                items = [{}] if is_account_level_check else []
        elif for_each:
            items = discovery_results.get(for_each, [])
        else:
            items = [{}] if is_account_level_check else []

    if (not items) and primary_items:
        items = primary_items

    if not items:
        if is_account_level_check:
            items = [{}]
        else:
            return []

    # Run check for each item
    check_results = []
    for item in items:
        context = {'item': item, 'params': params}

        def eval_conditions(cond_config):
            if 'all' in cond_config:
                return all(eval_conditions(sub_cond) for sub_cond in cond_config['all'])
            elif 'any' in cond_config:
                return any(eval_conditions(sub_cond) for sub_cond in cond_config['any'])
            else:
                var = cond_config.get('var')
                op = cond_config.get('op')
                value = cond_config.get('value')

                if isinstance(value, str) and '{{' in value:
                    value = resolve_template(value, context)

                actual_value = extract_value(context, var) if var else None
                return evaluate_condition(actual_value, op, value)

        try:
            result = eval_conditions(conditions)
            status = 'PASS' if result else 'FAIL'
        except Exception as e:
            logger.warning(f"Error evaluating {check_id}: {e}")
            status = 'ERROR'

        checked_fields = extract_checked_fields(conditions)

        created_at = datetime.utcnow().isoformat() + 'Z'

        results_mode = os.getenv("RESULTS_NDJSON_MODE", "finding").strip().lower()
        is_verbose = results_mode in ("legacy",)

        record = {
            'rule_id': check_id,
            'result': status,
            'status': status,
            'service': service_name,
            'region': region,
            'created_at': created_at,
            '_checked_fields': list(checked_fields),
        }

        if is_verbose:
            record.update({
                'title': title,
                'severity': severity,
                'assertion_id': assertion_id,
            })

        if item:
            check_discovery_id = independent_disc_id if independent_disc_id else (
                for_each.get('discovery') if isinstance(for_each, dict) else (
                    str(for_each) if for_each else None
                )
            )

            resource_info = extract_resource_identifier(item, service_name, region, account_id, discovery_id=check_discovery_id)

            record['resource_uid'] = resource_info['resource_uid']
            record['resource_arn'] = resource_info['resource_arn']
            record['resource_id'] = resource_info['resource_id']
            record['resource_type'] = resource_info['resource_type']
            record['resource_name'] = item.get('Name') or item.get('name') or resource_info.get('resource_id') or ''

        check_results.append(record)

    return check_results
