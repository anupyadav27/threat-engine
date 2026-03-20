"""
AWS Discovery Scanner — service orchestration and AWSDiscoveryScanner interface.

Utility functions (extraction, conditions, rules, boto helpers, dependency graph)
have been extracted into providers.aws.utils.* modules.
"""
import asyncio
import json
import os
import boto3
import logging
import time
from typing import Any, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from botocore.exceptions import ClientError
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent


from common.utils.reporting_manager import save_reporting_bundle
from providers.aws.auth.aws_auth import get_boto3_session, get_session_for_account

# ── Extracted utility modules (relative imports to avoid circular __init__.py) ─
from ..aws_utils.extraction import (
    extract_value,
    _emit_trace_enabled,
    extract_checked_fields,
    auto_emit_arn_and_name,
    extract_resource_identifier,
)
from ..aws_utils.conditions import evaluate_condition, resolve_template
from ..aws_utils.rules import load_service_rules, normalize_to_phase2_format
from ..aws_utils.boto_helpers import (
    BOTO_CONFIG,
    OPERATION_TIMEOUT,
    MAX_ITEMS_PER_DISCOVERY,
    _normalize_action,
    _is_expected_aws_error,
    _is_permanent_error,
    _retry_call,
    _call_with_timeout,
    _paginate_api_call,
    _manual_paginate_with_token,
)
from ..aws_utils.dependencies import (
    _build_dependency_graph,
    _enrich_inventory_with_dependent_discoveries,
    _resolve_check_dependencies,
    _match_items,
    _run_single_check,
)

# Database-driven configuration (Phase 4: Unified Service Execution)
# In Docker: engine_discoveries/ is the COPY root. Locally: engines/discoveries/
# Both paths are tried so imports work in both environments.
_discoveries_root = _project_root()  # engines/discoveries/ (4 levels up from this file)
sys.path.append(str(_discoveries_root))
sys.path.append(str(_project_root() / "engine_discoveries"))  # Docker COPY destination
from utils.config_loader import DiscoveryConfigLoader
from utils.filter_engine import FilterEngine
from utils.pagination_engine import PaginationEngine

# Initialize database-driven configuration loaders (cached for performance)
_config_loader = None
_filter_engine = None
_pagination_engine = None


def _get_config_loader():
    """Get singleton DiscoveryConfigLoader instance"""
    global _config_loader, _filter_engine, _pagination_engine
    if _config_loader is None:
        _config_loader = DiscoveryConfigLoader(provider='aws')
        _filter_engine = FilterEngine(_config_loader)
        _pagination_engine = PaginationEngine(_config_loader)
    return _config_loader, _filter_engine, _pagination_engine


logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-boto3')

# Dedicated thread pool for concurrent service-region scans.
import concurrent.futures as _cf
_SCAN_EXECUTOR = _cf.ThreadPoolExecutor(
    max_workers=int(os.getenv('SCAN_EXECUTOR_THREADS', '400')),
    thread_name_prefix='disc-scan',
)


def run_service(
    service_name: str,
    region: Optional[str] = None,
    session_override: Optional[boto3.session.Session] = None,
    service_rules_override: Optional[Dict[str, Any]] = None,
    skip_checks: bool = False
):
    """
    Unified service execution for both global and regional services.

    This function replaces the duplicated run_global_service() and run_regional_service() functions,
    eliminating 1,756 lines of code duplication by parametrizing the region.

    Args:
        service_name: Service name (e.g., 'iam', 'ec2')
        region: AWS region. If None, determined from database scope column:
                - scope='global' → uses 'us-east-1'
                - scope='regional' → raises error (must provide region)
        session_override: Optional boto3 session
        service_rules_override: Optional service rules override (for regional services)
        skip_checks: If True, skip check phase (discovery only)

    Returns:
        Dict containing:
            - inventory: discovery results
            - checks: check results (empty if skip_checks=True)
            - service: service name
            - scope: 'global' or 'regional'
            - region: execution region (always present)
            - _raw_data: raw API responses

    Raises:
        ValueError: If region is None for a regional service

    Examples:
        >>> # Global service (IAM) - region auto-determined from database
        >>> result = run_service('iam')
        >>> result['scope']  # 'global'
        >>> result['region']  # 'us-east-1'

        >>> # Regional service (EC2) - region must be provided
        >>> result = run_service('ec2', region='us-west-2')
        >>> result['scope']  # 'regional'
        >>> result['region']  # 'us-west-2'
    """
    # Track scan attempt metadata
    scan_start_time = time.time()
    scan_result = {
        'service': service_name,
        'region': region or 'auto',
        'status': 'pending',
        'discoveries': 0,
        'error': None,
        'error_message': None
    }

    try:
        # Load database-driven configuration
        config_loader, filter_engine, pagination_engine = _get_config_loader()

        # Determine scope from database
        scope = config_loader.get_scope(service_name)

        # Determine execution region
        if region is None:
            if scope == 'global':
                execution_region = 'us-east-1'
                logger.info(f"[UNIFIED] {service_name}: Global service, using region=us-east-1")
            else:
                raise ValueError(
                    f"Service '{service_name}' has scope='{scope}' (regional), "
                    f"but no region was provided. Regional services require explicit region parameter."
                )
        else:
            execution_region = region
            logger.info(f"[UNIFIED] {service_name}: Using provided region={execution_region}")

        # Get boto3 client name from database (replaces hardcoded discovery_helper mapping)
        boto3_client_name = config_loader.get_boto3_client_name(service_name)
        logger.info(f"[UNIFIED] {service_name}: boto3_client_name={boto3_client_name} (from database)")

        # Load service rules
        service_rules = service_rules_override or load_service_rules(service_name)

        # Create session with execution region
        session = session_override or get_boto3_session(default_region=execution_region)
        client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

        # Extract account_id for resource identifier generation
        account_id = None
        try:
            sts_client = session.client('sts', region_name=execution_region, config=BOTO_CONFIG)
            account_id = sts_client.get_caller_identity().get('Account')
        except Exception as e:
            logger.debug(f"Could not get account ID for resource identifiers: {e}")

        discovery_results = {}
        saved_data = {}

        # Build dependency graph for parallel processing of independent discoveries
        all_discoveries = service_rules.get('discovery', [])
        dependency_graph = _build_dependency_graph(all_discoveries)
        independent_discoveries = dependency_graph['independent']
        dependent_groups = dependency_graph['dependent_groups']

        # Thread-safe locks for shared state
        saved_data_lock = Lock()
        discovery_results_lock = Lock()

        # ============================================================
        # PHASE 1: DISCOVERY - Run ALL discoveries, store in memory
        # ============================================================
        discovery_start_time = time.time()

        # Process independent discoveries in parallel, then dependent sequentially.
        # A single shared semaphore bounds ALL concurrent API calls for this service:
        # both the outer discovery threads AND inner for_each expansions share it.
        # This prevents the nested-threadpool OOM where 50 outer * 50 inner = 2500 threads.
        max_discovery_workers = int(os.getenv('MAX_DISCOVERY_WORKERS', '20'))
        for_each_max_workers = int(os.getenv('FOR_EACH_MAX_WORKERS', '10'))

        if independent_discoveries:
            logger.info(f"Processing {len(independent_discoveries)} independent discoveries in parallel (max {max_discovery_workers} workers)")
            discovery_futures = {}

            def process_independent_discovery(discovery):
                """Process a single independent discovery (called in parallel) - uses same logic as dependent discoveries"""
                discovery_id = discovery['discovery_id']
                disc_start = time.time()
                logger.info(f"Processing discovery: {discovery_id}")

                # Create thread-local client for this discovery
                local_client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

                # Track save_as for emit processing (use first call's save_as)
                discovery_save_as = None

                # Process calls in order
                for call in discovery.get('calls', []):
                    action = _normalize_action(call['action'])
                    params = call.get('params', {})
                    save_as = call.get('save_as', f'{action}_response')
                    if discovery_save_as is None:
                        discovery_save_as = save_as
                    for_each = discovery.get('for_each') or call.get('for_each')
                    as_var = call.get('as', 'item')
                    on_error = discovery.get('on_error') or call.get('on_error', 'continue')

                    try:
                        if for_each:
                            # Dependent discoveries only - skip for independent
                            items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                            with saved_data_lock:
                                items = discovery_results.get(items_ref)
                                if items is None:
                                    items = extract_value(saved_data, items_ref)
                            # Independent discoveries shouldn't have for_each - log warning
                            if items:
                                logger.warning(f"Independent discovery {discovery_id} has for_each - treating as dependent")
                        else:
                            # Regular call - thread-safe access to saved_data
                            call_client = local_client
                            specified_client = call.get('client', service_name)
                            if specified_client != service_name:
                                call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)

                            # Thread-safe read of saved_data
                            with saved_data_lock:
                                context = saved_data.copy()

                            def resolve_params_recursive(obj, context):
                                """Recursively resolve template variables in params, with validation for QuickSight AwsAccountId"""
                                if isinstance(obj, dict):
                                    resolved = {}
                                    for key, value in obj.items():
                                        resolved_value = resolve_params_recursive(value, context)
                                        # Validate QuickSight AwsAccountId - ensure it's not 0 or empty
                                        if key == 'AwsAccountId' and service_name == 'quicksight':
                                            if resolved_value == '0' or resolved_value == 0 or resolved_value == '':
                                                # Try to get account ID from STS if account_info is invalid
                                                try:
                                                    sts_client = session.client('sts', region_name=execution_region, config=BOTO_CONFIG)
                                                    account_id_from_sts = sts_client.get_caller_identity().get('Account')
                                                    if account_id_from_sts:
                                                        resolved_value = str(account_id_from_sts)
                                                        logger.debug(f"QuickSight: Fixed invalid AwsAccountId (was {obj.get('AwsAccountId')}), using {resolved_value}")
                                                except Exception as e:
                                                    logger.warning(f"QuickSight: Could not get account ID from STS: {e}")
                                        resolved[key] = resolved_value
                                    return resolved
                                elif isinstance(obj, list):
                                    return [resolve_params_recursive(item, context) for item in obj]
                                elif isinstance(obj, str):
                                    return resolve_template(obj, context)
                                else:
                                    return obj

                            resolved_params = resolve_params_recursive(params, context)

                            # Apply AWS-managed resource filters at API level (before API call)
                            # Using database-driven FilterEngine
                            resolved_params = filter_engine.apply_api_filters(
                                discovery_id, resolved_params, service_name, account_id
                            )

                            # Check if operation supports pagination using can_paginate (no hardcoding)
                            is_list_or_describe = (
                                action.startswith('list_') or
                                action.startswith('describe_') or
                                action.startswith('get_')
                            )

                            # Use pagination for list/describe operations (independent discoveries only)
                            if not for_each and is_list_or_describe:
                                # Check if boto3 paginator is available (most reliable method)
                                try:
                                    if call_client.can_paginate(action):
                                        # Use robust pagination with safeguards
                                        response = _paginate_api_call(
                                            call_client,
                                            action,
                                            resolved_params,
                                            discovery_config=discovery,
                                            operation_timeout=OPERATION_TIMEOUT
                                        )
                                    else:
                                        # No paginator - use single call with timeout protection
                                        logger.debug(f"{action} doesn't support boto3 paginator, using single call with timeout")
                                        response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                                except Exception as e:
                                    # Fallback: single call with timeout
                                    logger.debug(f"Error checking pagination for {action}, using single call: {e}")
                                    response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                            else:
                                # Single API call (no pagination) with timeout protection
                                response = _call_with_timeout(call_client, action, resolved_params, timeout=300)

                            if save_as:
                                # Thread-safe write to saved_data
                                with saved_data_lock:
                                    if 'fields' in call:
                                        extracted_data = {}
                                        for field in call['fields']:
                                            value = extract_value(response, field)
                                            if value is not None:
                                                if field.endswith('[]'):
                                                    extracted_data = value
                                                else:
                                                    parts = field.split('.')
                                                    current = extracted_data
                                                    for part in parts[:-1]:
                                                        if part not in current:
                                                            current[part] = {}
                                                        current = current[part]
                                                    current[parts[-1]] = value
                                        saved_data[save_as] = extracted_data
                                    else:
                                        saved_data[save_as] = response
                                    saved_data[f'_discovery_{save_as}'] = discovery_id
                    except Exception as e:
                        if on_error == 'continue':
                            if _is_expected_aws_error(e):
                                logger.debug(f"Skipped {action}: {e}")
                            else:
                                logger.warning(f"Failed {action}: {e}")
                            continue
                        else:
                            raise

                # Process emit - thread-safe read/write
                emit_config = discovery.get('emit', {})
                discovery_for_each = discovery.get('for_each')

                # Read saved_data thread-safely
                with saved_data_lock:
                    saved_data_copy = saved_data.copy()

                # Process emit logic
                if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data_copy:
                    accumulated_contexts = saved_data_copy[f'{discovery_save_as}_contexts']
                    results = []
                    if 'items_for' in emit_config:
                        items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                        as_var = emit_config.get('as', 'r')
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']
                            context = acc_data['context']
                            response_items = extract_value(response, items_path)

                            # Filter out AWS-managed resources (customer-managed only)
                            # Using database-driven FilterEngine
                            response_items = filter_engine.apply_response_filters(
                                discovery_id, response_items, service_name, account_id
                            )

                            if response_items:
                                for response_item in response_items:
                                    if isinstance(response_item, dict):
                                        item_data = response_item.copy()
                                        auto_fields = auto_emit_arn_and_name(response_item, service=service_name, region=execution_region, account_id=account_id)
                                        for key, value in auto_fields.items():
                                            if key not in item_data:
                                                item_data[key] = value
                                    else:
                                        item_data = {'_raw_item': response_item}

                                    # Preserve resource_arn from parent item
                                    if isinstance(item, dict):
                                        parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                        if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                            item_data['resource_arn'] = parent_arn

                                    results.append(item_data)
                    else:
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']

                            if not isinstance(response, dict):
                                logger.warning(f"[EMIT] {discovery_id}: response is not a dict, skipping emit")
                                continue

                            item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}

                            if isinstance(item, dict):
                                parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                    item_data['resource_arn'] = parent_arn

                            results.append(item_data)

                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    items = extract_value(saved_data_copy, items_path)

                    # Filter out AWS-managed resources using database-driven FilterEngine
                    items = filter_engine.apply_response_filters(discovery_id, items, service_name, account_id)

                    results = []
                    if items:
                        for item in items:
                            if isinstance(item, dict):
                                item_data = item.copy()
                                auto_fields = auto_emit_arn_and_name(item, service=service_name, region=execution_region, account_id=account_id)
                                for key, value in auto_fields.items():
                                    if key not in item_data:
                                        item_data[key] = value
                                # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                                resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                                for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                                    if resource_info.get(key) and not item_data.get(key):
                                        item_data[key] = resource_info[key]
                                # Store raw response for DB raw_response column
                                if '_raw_response' not in item_data:
                                    item_data['_raw_response'] = {k: v for k, v in item_data.items()
                                                                   if not k.startswith('_') and k not in ('resource_arn', 'resource_uid', 'resource_id', 'resource_type', 'resource_name')}
                            else:
                                item_data = {'_raw_item': item}

                            results.append(item_data)

                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'item' in emit_config:
                    response = saved_data_copy.get('response', {})
                    if isinstance(response, dict):
                        item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                        # Store raw response for DB raw_response column
                        item_data['_raw_response'] = dict(item_data)
                    else:
                        item_data = {'_raw_response': response}

                    auto_fields = auto_emit_arn_and_name(saved_data_copy, service=service_name, region=execution_region, account_id=account_id)
                    for key, value in auto_fields.items():
                        if key not in item_data:
                            item_data[key] = value
                    # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                    resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                    for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                        if resource_info.get(key) and not item_data.get(key):
                            item_data[key] = resource_info[key]

                    with discovery_results_lock:
                        discovery_results[discovery_id] = [item_data]

                disc_elapsed = time.time() - disc_start
                logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")

            # Process independent discoveries in parallel.
            # max_workers here controls queue depth; actual concurrency is
            # further gated by _service_semaphore acquired inside each task.
            with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_discovery_workers)) as executor:
                for discovery in independent_discoveries:
                    future = executor.submit(process_independent_discovery, discovery)
                    discovery_futures[future] = discovery.get('discovery_id')

                for future in as_completed(discovery_futures):
                    discovery_id = discovery_futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Failed to process independent discovery {discovery_id}: {e}")

        # Process dependent discoveries sequentially
        processed_ids = {disc.get('discovery_id') for disc in independent_discoveries}
        remaining_discoveries = [disc for disc in all_discoveries if disc.get('discovery_id') not in processed_ids]

        for discovery in remaining_discoveries:
            discovery_id = discovery['discovery_id']
            disc_start = time.time()
            logger.info(f"Processing discovery: {discovery_id}")

            discovery_save_as = None

            for call in discovery.get('calls', []):
                action = _normalize_action(call['action'])
                params = call.get('params', {})
                save_as = call.get('save_as', f'{action}_response')
                if discovery_save_as is None:
                    discovery_save_as = save_as
                for_each = discovery.get('for_each') or call.get('for_each')
                as_var = call.get('as', 'item')
                on_error = discovery.get('on_error') or call.get('on_error', 'continue')

                try:
                    if for_each:
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        items = discovery_results.get(items_ref)
                        if items is None:
                            items = extract_value(saved_data, items_ref)

                        if items:
                            accumulated_responses = []
                            accumulated_responses_lock = Lock()

                            def process_item(item):
                                item_context = {as_var: item}
                                item_context.update(saved_data)

                                def resolve_params_recursive(obj, context):
                                    if isinstance(obj, dict):
                                        return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                                    elif isinstance(obj, list):
                                        return [resolve_params_recursive(item, context) for item in obj]
                                    elif isinstance(obj, str):
                                        return resolve_template(obj, context)
                                    else:
                                        return obj

                                resolved_params = resolve_params_recursive(params, item_context)

                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)
                                else:
                                    call_client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

                                try:
                                    response = _retry_call(getattr(call_client, action), **resolved_params)
                                    return {'response': response, 'item': item, 'context': item_context}
                                except Exception as api_error:
                                    if on_error == 'continue':
                                        if _is_expected_aws_error(api_error):
                                            logger.debug(f"Skipped {action}: {api_error}")
                                        else:
                                            logger.warning(f"Failed {action}: {api_error}")
                                        return None
                                    else:
                                        raise

                            max_workers = min(len(items), for_each_max_workers)
                            logger.info(f"Starting parallel execution for {discovery_id}: {len(items)} items with {max_workers} workers")

                            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                                futures = [executor.submit(process_item, item) for item in items]
                                for future in as_completed(futures):
                                    try:
                                        result = future.result()
                                        if result:
                                            with accumulated_responses_lock:
                                                accumulated_responses.append(result)
                                    except Exception as e:
                                        if on_error == 'continue':
                                            logger.warning(f"Unexpected error in parallel execution: {e}")
                                        else:
                                            raise

                            if save_as and accumulated_responses:
                                saved_data[save_as] = [r['response'] for r in accumulated_responses]
                                saved_data[f'{save_as}_contexts'] = accumulated_responses
                                saved_data[f'_discovery_{save_as}'] = discovery_id
                    else:
                        # Regular call
                        call_client = client
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)

                        context = saved_data.copy()
                        def resolve_params_recursive(obj, context):
                            if isinstance(obj, dict):
                                return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                            elif isinstance(obj, list):
                                return [resolve_params_recursive(item, context) for item in obj]
                            elif isinstance(obj, str):
                                return resolve_template(obj, context)
                            else:
                                return obj

                        resolved_params = resolve_params_recursive(params, context)
                        # Apply API-level filters using database-driven FilterEngine
                        resolved_params = filter_engine.apply_api_filters(discovery_id, resolved_params, service_name, account_id)

                        is_list_or_describe = (action.startswith('list_') or action.startswith('describe_') or action.startswith('get_'))

                        if not for_each and is_list_or_describe:
                            try:
                                if call_client.can_paginate(action):
                                    response = _paginate_api_call(call_client, action, resolved_params, discovery_config=discovery, operation_timeout=OPERATION_TIMEOUT)
                                else:
                                    response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                            except Exception as e:
                                response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                        else:
                            response = _call_with_timeout(call_client, action, resolved_params, timeout=300)

                        if save_as:
                            if 'fields' in call:
                                extracted_data = {}
                                for field in call['fields']:
                                    value = extract_value(response, field)
                                    if value is not None:
                                        if field.endswith('[]'):
                                            extracted_data = value
                                        else:
                                            parts = field.split('.')
                                            current = extracted_data
                                            for part in parts[:-1]:
                                                if part not in current:
                                                    current[part] = {}
                                                current = current[part]
                                            current[parts[-1]] = value
                                saved_data[save_as] = extracted_data
                            else:
                                saved_data[save_as] = response
                            saved_data[f'_discovery_{save_as}'] = discovery_id
                except Exception as e:
                    if on_error == 'continue':
                        if _is_expected_aws_error(e):
                            logger.debug(f"Skipped {action}: {e}")
                        else:
                            logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise

            # Process emit
            emit_config = discovery.get('emit', {})
            discovery_for_each = discovery.get('for_each')

            if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data:
                accumulated_contexts = saved_data[f'{discovery_save_as}_contexts']
                results = []

                if 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    for acc_data in accumulated_contexts:
                        response = acc_data['response']
                        item = acc_data['item']
                        response_items = extract_value(response, items_path)
                        # Apply response filters using database-driven FilterEngine
                        response_items = filter_engine.apply_response_filters(discovery_id, response_items, service_name, account_id)

                        if response_items:
                            for response_item in response_items:
                                if isinstance(response_item, dict):
                                    item_data = response_item.copy()
                                    auto_fields = auto_emit_arn_and_name(response_item, service=service_name, region=execution_region, account_id=account_id)
                                    for key, value in auto_fields.items():
                                        if key not in item_data:
                                            item_data[key] = value
                                else:
                                    item_data = {'_raw_item': response_item}

                                if isinstance(item, dict):
                                    parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                    if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                        item_data['resource_arn'] = parent_arn

                                results.append(item_data)
                else:
                    for acc_data in accumulated_contexts:
                        response = acc_data['response']
                        item = acc_data['item']

                        if not isinstance(response, dict):
                            continue

                        item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}

                        if isinstance(item, dict):
                            parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                            if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                item_data['resource_arn'] = parent_arn

                        results.append(item_data)

                discovery_results[discovery_id] = results
            elif 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                items = extract_value(saved_data, items_path)
                # Apply response filters using database-driven FilterEngine
                items = filter_engine.apply_response_filters(discovery_id, items, service_name, account_id)

                results = []
                if items:
                    for item in items:
                        if isinstance(item, dict):
                            item_data = item.copy()
                            auto_fields = auto_emit_arn_and_name(item, service=service_name, region=execution_region, account_id=account_id)
                            for key, value in auto_fields.items():
                                if key not in item_data:
                                    item_data[key] = value
                            # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                            resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                            for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                                if resource_info.get(key) and not item_data.get(key):
                                    item_data[key] = resource_info[key]
                            # Store raw response for DB raw_response column
                            if '_raw_response' not in item_data:
                                item_data['_raw_response'] = {k: v for k, v in item_data.items()
                                                               if not k.startswith('_') and k not in ('resource_arn', 'resource_uid', 'resource_id', 'resource_type', 'resource_name')}
                        else:
                            item_data = {'_raw_item': item}
                        results.append(item_data)

                discovery_results[discovery_id] = results
            elif 'item' in emit_config:
                response = saved_data.get('response', {})
                if isinstance(response, dict):
                    item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                    # Store raw response for DB raw_response column
                    item_data['_raw_response'] = dict(item_data)
                else:
                    item_data = {'_raw_response': response}

                auto_fields = auto_emit_arn_and_name(saved_data, service=service_name, region=execution_region, account_id=account_id)
                for key, value in auto_fields.items():
                    if key not in item_data:
                        item_data[key] = value
                # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                    if resource_info.get(key) and not item_data.get(key):
                        item_data[key] = resource_info[key]

                discovery_results[discovery_id] = [item_data]

            disc_elapsed = time.time() - disc_start
            logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")

        # ============================================================
        # PHASE 2: BUILD INVENTORY
        # ============================================================
        try:
            discovery_results = _enrich_inventory_with_dependent_discoveries(
                discovery_results, service_rules, dependency_graph
            )
        except Exception as e:
            logger.warning(f"Failed to enrich inventory: {e}")

        # Compute primary inventory items
        primary_items = None
        try:
            from common.utils.reporting_manager import is_cspm_inventory_resource
            for disc in service_rules.get("discovery", []) or []:
                did = disc.get("discovery_id")
                if not did:
                    continue
                items_candidate = discovery_results.get(did)
                if not (isinstance(items_candidate, list) and items_candidate):
                    continue
                if not is_cspm_inventory_resource(did, discovery_config=disc):
                    continue
                primary_items = items_candidate
                break
        except Exception:
            primary_items = None

        # ============================================================
        # PHASE 3: CHECKS - Run ALL checks in parallel
        # ============================================================
        all_checks = service_rules.get('checks', [])
        checks_output = []

        if skip_checks:
            logger.info("Skipping checks (discovery-only mode)")
            all_checks = []
        else:
            max_check_workers = int(os.getenv('MAX_CHECK_WORKERS', '50'))

        if all_checks:
            logger.info(f"Running {len(all_checks)} checks in parallel (max {max_check_workers} workers)")

            with ThreadPoolExecutor(max_workers=max_check_workers) as executor:
                futures = {
                    executor.submit(
                        _run_single_check,
                        check,
                        service_name,
                        execution_region,
                        account_id,
                        discovery_results,
                        service_rules,
                        primary_items
                    ): check
                    for check in all_checks
                }

                for future in as_completed(futures):
                    check = futures[future]
                    try:
                        results = future.result()
                        checks_output.extend(results)
                    except Exception as e:
                        logger.error(f"Check {check.get('rule_id', 'unknown')} failed: {e}")

        # Calculate total discoveries
        total_discoveries = sum(len(items) for items in discovery_results.values() if isinstance(items, list))

        # Update scan result metadata
        scan_result['status'] = 'scanned'
        scan_result['discoveries'] = total_discoveries
        scan_result['region'] = execution_region
        scan_result['duration_ms'] = int((time.time() - scan_start_time) * 1000)

        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': scope,
            'region': execution_region,
            '_raw_data': saved_data,
            '_scan_metadata': scan_result  # NEW: Scan attempt tracking
        }

    except Exception as e:
        import traceback
        from botocore.exceptions import ClientError

        # Determine error type and categorize scan status
        error_code = None
        error_message = str(e)

        if isinstance(e, ClientError):
            error_code = e.response['Error']['Code']
            error_message = e.response['Error'].get('Message', str(e))

            # Categorize AWS error codes
            if error_code in ('OptInRequired', 'SubscriptionRequiredException', 'InvalidAction'):
                # Service not enabled - this is NORMAL, not an error
                scan_result['status'] = 'unavailable'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.info(f"Service {service_name} not enabled in {region or 'auto'}: {error_code}")
            elif error_code in ('AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException'):
                # Permission issue - record but don't fail the overall scan
                scan_result['status'] = 'access_denied'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.warning(f"No permission for {service_name} in {region or 'auto'}: {error_code}")
            else:
                # Unexpected AWS error
                scan_result['status'] = 'failed'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.error(f"Service {service_name} (region={region}) failed: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
        else:
            # Non-AWS error (timeout, network, etc.)
            scan_result['status'] = 'failed'
            scan_result['error'] = type(e).__name__
            scan_result['error_message'] = error_message
            logger.error(f"Service {service_name} (region={region}) failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")

        # Finalize scan metadata
        scan_result['region'] = region or 'us-east-1'
        scan_result['duration_ms'] = int((time.time() - scan_start_time) * 1000)

        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': scope if 'scope' in locals() else 'unknown',
            'region': region or 'us-east-1',
            'unavailable': True,
            'error': error_code or str(e),
            '_scan_metadata': scan_result  # NEW: Scan attempt tracking
        }
def run_global_service(service_name, session_override: Optional[boto3.session.Session] = None, skip_checks: bool = False):
    """
    Legacy wrapper for backward compatibility.
    
    Calls unified run_service() with region=None (auto-determined from database scope).
    
    Args:
        service_name: Service name (e.g., 'iam')
        session_override: Optional boto3 session
        skip_checks: If True, skip check phase (discovery only)
    
    Returns:
        Same format as run_service()
    
    Deprecated: Use run_service() directly for new code.
    """
    logger.info(f"[WRAPPER] run_global_service() → run_service(service_name='{service_name}', region=None)")
    return run_service(
        service_name=service_name,
        region=None,  # Auto-determined from database (global services use us-east-1)
        session_override=session_override,
        service_rules_override=None,
        skip_checks=skip_checks
    )


def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None, service_rules_override: Optional[Dict[str, Any]] = None, skip_checks: bool = False):
    """
    Legacy wrapper for backward compatibility.
    
    Calls unified run_service() with explicit region parameter.
    
    Args:
        service_name: Service name (e.g., 'ec2')
        region: AWS region (e.g., 'us-east-1')
        session_override: Optional boto3 session
        service_rules_override: Optional service rules override
        skip_checks: If True, skip check phase (discovery only)
    
    Returns:
        Same format as run_service()
    
    Deprecated: Use run_service() directly for new code.
    """
    logger.info(f"[WRAPPER] run_regional_service() → run_service(service_name='{service_name}', region='{region}')")
    return run_service(
        service_name=service_name,
        region=region,  # Explicit region for regional services
        session_override=session_override,
        service_rules_override=service_rules_override,
        skip_checks=skip_checks
    )


# ============================================================================
# AWS Discovery Scanner - DiscoveryScanner Interface Implementation
# ============================================================================

class AWSDiscoveryScanner:
    """
    AWS implementation of the DiscoveryScanner interface.

    This scanner wraps the existing AWS discovery logic (run_service function)
    and provides a consistent interface for the common discovery engine.

    It handles:
    - AWS authentication via boto3
    - Service discovery execution
    - Resource identification
    - Scan tracking metadata
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        """
        Initialize AWS scanner with credentials.

        Args:
            credentials: AWS credentials dictionary with:
                - role_arn: IAM role ARN to assume
                - external_id: External ID for AssumeRole
                - access_key_id: (optional) AWS access key
                - secret_access_key: (optional) AWS secret key
                - session_token: (optional) AWS session token
            **kwargs: Additional configuration:
                - provider: 'aws' (default)
                - default_region: Default region for global services
        """
        self.credentials = credentials
        self.provider = kwargs.get('provider', 'aws')
        self.default_region = kwargs.get('default_region', 'us-east-1')
        self.session = None
        self.account_id = None

    def authenticate(self):
        """
        Authenticate to AWS using provided credentials.

        Creates a boto3 session using IAM role assumption or access keys.

        Returns:
            boto3.Session: Authenticated session

        Raises:
            AuthenticationError: If authentication fails
        """
        from common.models.provider_interface import AuthenticationError

        try:
            role_arn = self.credentials.get('role_arn')
            external_id = self.credentials.get('external_id')

            # Credentials may be nested under 'credentials' key (Secrets Manager format)
            nested_creds = self.credentials.get('credentials', {}) or {}
            access_key_id = self.credentials.get('access_key_id') or nested_creds.get('access_key_id')
            secret_access_key = self.credentials.get('secret_access_key') or nested_creds.get('secret_access_key')
            session_token = self.credentials.get('session_token') or nested_creds.get('session_token')

            if role_arn:
                # Use role assumption (preferred)
                # Parse role_arn → account_id + role_name for get_session_for_account()
                # Format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
                arn_parts = role_arn.split(':')
                parsed_account_id = arn_parts[4] if len(arn_parts) > 4 else self.account_id
                parsed_role_name = arn_parts[5].split('/')[-1] if len(arn_parts) > 5 else role_arn
                self.session = get_session_for_account(
                    account_id=parsed_account_id,
                    role_name=parsed_role_name,
                    external_id=external_id,
                    default_region=self.default_region
                )
            elif access_key_id and secret_access_key:
                # Use explicit access keys from Secrets Manager
                import boto3
                self.session = boto3.Session(
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    aws_session_token=session_token,
                    region_name=self.default_region
                )
                logger.info(f"Authenticated to AWS using access key (key_id ending: ...{access_key_id[-4:]})")
            else:
                # Use default credentials (pod IAM role)
                self.session = get_boto3_session(default_region=self.default_region)

            # Get account ID
            try:
                sts = self.session.client('sts', region_name=self.default_region)
                self.account_id = sts.get_caller_identity()['Account']
                logger.info(f"Authenticated to AWS account: {self.account_id}")
            except Exception as e:
                logger.warning(f"Could not get AWS account ID: {e}")
                self.account_id = 'unknown'

            return self.session

        except Exception as e:
            logger.error(f"AWS authentication failed: {e}")
            raise AuthenticationError(f"Failed to authenticate to AWS: {e}")

    async def list_available_regions(self) -> List[str]:
        """
        Return all opted-in regions for this AWS account via ec2:describe_regions.

        Called once before the service scan loop to determine which regions to scan
        when include_regions is not specified in scan_orchestration.

        Returns:
            Sorted list of enabled region names (opt-in-not-required + opted-in)
        """
        import functools
        if not self.session:
            self.authenticate()
        loop = asyncio.get_event_loop()

        def _describe_regions():
            ec2 = self.session.client('ec2', region_name='us-east-1', config=BOTO_CONFIG)
            resp = ec2.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            return sorted(r['RegionName'] for r in resp['Regions'])

        regions = await loop.run_in_executor(None, _describe_regions)
        logger.info(f"Discovered {len(regions)} available AWS regions: {regions}")
        return regions

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Execute service discovery for an AWS service.

        This method wraps the existing run_service() function and extracts:
        - Discovered resources from 'inventory' key
        - Scan metadata from '_scan_metadata' key

        Args:
            service: AWS service name (e.g., 'ec2', 'iam', 's3')
            region: AWS region (e.g., 'us-east-1')
            config: Discovery configuration from rule_discoveries.discoveries_data

        Returns:
            Tuple of (discoveries, scan_metadata):
            - discoveries: List of discovered resources
            - scan_metadata: Scan tracking metadata (status, discoveries count, etc.)

        Raises:
            DiscoveryError: If discovery fails
        """
        from common.models.provider_interface import DiscoveryError

        try:
            # Ensure authenticated
            if not self.session:
                self.authenticate()

            # Run the CPU/IO-bound run_service() in a thread pool executor so the
            # asyncio event loop stays free to handle health check probes during
            # heavy scans. Without this, the liveness probe times out and the
            # kubelet kills the pod mid-scan (exit code 137).
            import asyncio, functools
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                _SCAN_EXECUTOR,  # dedicated pool: 100 threads vs default ~8
                functools.partial(
                    run_service,
                    service_name=service,
                    region=region,
                    session_override=self.session,
                    service_rules_override=config,
                    skip_checks=True
                )
            )

            # Extract discoveries from 'inventory' key
            inventory = result.get('inventory', {})
            all_discoveries = []

            # Flatten all discovery results, tagging each item with its operation discovery_id
            # and extracting resource_type from the item's ARN / ID patterns.
            account_id = self.account_id or 'unknown'
            for discovery_id, items in inventory.items():
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if '_discovery_id' not in item:
                            item['_discovery_id'] = discovery_id
                        if not item.get('resource_type'):
                            try:
                                rinfo = extract_resource_identifier(
                                    item, service, region, account_id,
                                    discovery_id=discovery_id
                                )
                                rtype = rinfo.get('resource_type')
                                if rtype and rtype != 'resource':
                                    item['resource_type'] = rtype
                            except Exception:
                                pass
                    all_discoveries.extend(items)

            # Extract scan metadata
            scan_metadata = result.get('_scan_metadata', {
                'service': service,
                'region': region,
                'status': 'scanned',
                'discoveries': len(all_discoveries),
                'error': None
            })

            logger.info(
                f"AWS discovery completed: service={service}, region={region}, "
                f"discoveries={scan_metadata['discoveries']}, status={scan_metadata['status']}"
            )

            return all_discoveries, scan_metadata

        except Exception as e:
            logger.error(f"AWS discovery failed for service={service}, region={region}: {e}")
            raise DiscoveryError(f"AWS discovery failed: {e}")

    def get_client(self, service: str, region: str):
        """
        Get AWS boto3 client for specific service and region.

        Args:
            service: AWS service name (e.g., 'ec2', 's3')
            region: AWS region

        Returns:
            boto3.client: Authenticated client instance
        """
        if not self.session:
            self.authenticate()

        client_name = self.get_service_client_name(service)
        return self.session.client(client_name, region_name=region, config=BOTO_CONFIG)

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Extract resource identifiers (ARN, ID, name) from AWS resource.

        Uses the existing auto_emit_arn_and_name() function for consistency.

        Args:
            item: AWS API response item (single resource)
            service: AWS service name
            region: AWS region
            account_id: AWS account ID
            resource_type: Optional resource type

        Returns:
            Dict with extracted identifiers:
            {
                'resource_arn': 'arn:aws:...',
                'resource_id': 'i-123...',
                'resource_name': 'my-resource',
                'resource_uid': 'arn:aws:...'
            }
        """
        # Use existing auto_emit_arn_and_name function
        identifiers = auto_emit_arn_and_name(
            item=item,
            service=service,
            region=region,
            account_id=account_id
        )

        # Ensure resource_uid is set (fallback to resource_arn)
        if 'resource_uid' not in identifiers and 'resource_arn' in identifiers:
            identifiers['resource_uid'] = identifiers['resource_arn']

        return identifiers

    def get_service_client_name(self, service: str) -> str:
        """
        Map service name to boto3 client name.

        Uses the existing get_boto3_client_name() function.

        Args:
            service: Service name from rule_discoveries table

        Returns:
            Boto3 client name
        """
        return get_boto3_client_name(service)

    def get_account_id(self) -> str:
        """
        Get AWS account ID from authenticated session.

        Returns:
            AWS account ID string
        """
        if not self.account_id:
            if not self.session:
                self.authenticate()

            try:
                sts = self.session.client('sts', region_name=self.default_region)
                self.account_id = sts.get_caller_identity()['Account']
            except Exception as e:
                logger.error(f"Could not get AWS account ID: {e}")
                self.account_id = 'unknown'

        return self.account_id


# ============================================================================
# Main entry point (for testing)
# ============================================================================

if __name__ == '__main__':
    main()
