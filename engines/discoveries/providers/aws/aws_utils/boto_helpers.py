"""
Boto3 API call helpers: retry logic, timeout protection, pagination.

Includes configuration constants (BOTO_CONFIG, timeouts, retry settings),
error classification, and robust paginated API call handling.

Extracted from service_scanner.py for maintainability.
"""
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from time import sleep
from typing import Any, Dict, Optional

from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

logger = logging.getLogger('compliance-boto3')

# ── Retry / backoff settings ────────────────────────────────────────────────
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))

# ── Botocore retry / timeout config ────────────────────────────────────────
BOTO_CONFIG = BotoConfig(
    retries={'max_attempts': int(os.getenv('BOTO_MAX_ATTEMPTS', '5')), 'mode': os.getenv('BOTO_RETRY_MODE', 'adaptive')},
    read_timeout=int(os.getenv('BOTO_READ_TIMEOUT', '120')),
    connect_timeout=int(os.getenv('BOTO_CONNECT_TIMEOUT', '10')),
    max_pool_connections=int(os.getenv('BOTO_MAX_POOL_CONNECTIONS', '100')),
)

# ── Operation-level timeout ────────────────────────────────────────────────
OPERATION_TIMEOUT = int(os.getenv('OPERATION_TIMEOUT', '60'))
MAX_ITEMS_PER_DISCOVERY = int(os.getenv('MAX_ITEMS_PER_DISCOVERY', '100000'))


def _normalize_action(action: str) -> str:
    """Convert camelCase action names to snake_case for boto3 compatibility.
    e.g. 'describeAccountAttributes' -> 'describe_account_attributes'
    """
    # Already snake_case - return as-is
    if '_' in action:
        return action
    # Convert camelCase to snake_case
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', action)
    return re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s).lower()


def _is_expected_aws_error(error: Exception) -> bool:
    """
    Check if an AWS error is an expected error (like NoSuchBucketPolicy, NoSuchCORSConfiguration, etc.)
    These are normal when optional configurations don't exist, so we shouldn't log warnings for them.
    """
    if not isinstance(error, ClientError):
        return False

    error_code = error.response.get('Error', {}).get('Code', '') if hasattr(error, 'response') else ''

    expected_patterns = [
        'NoSuch',
        'NotFound',
        'MissingParameter',
    ]

    return any(pattern in error_code for pattern in expected_patterns)


def _is_permanent_error(e: Exception) -> bool:
    """Return True for errors that should never be retried (fail fast).

    Checks both:
    - Exception class name  (botocore raises typed exceptions)
    - String representation (catch-all for wrapped or unknown types)
    """
    err_type = type(e).__name__
    err_str = str(e)

    # ── Boto3 / botocore typed exceptions ──────────────────────────────────
    if err_type in ('EndpointConnectionError', 'ConnectTimeoutError', 'ReadTimeoutError'):
        return True

    # ── String-based checks ────────────────────────────────────────────────
    if 'Parameter validation failed' in err_str:
        return True
    if 'Unknown parameter in input' in err_str:
        return True
    if 'AccessDenied' in err_str or 'AuthFailure' in err_str:
        return True
    if 'Could not connect to the endpoint URL' in err_str:
        return True
    if 'Could not connect to the endpoint' in err_str:
        return True
    if 'InvalidClientTokenId' in err_str:
        return True
    return False


def _retry_call(func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Don't retry expected AWS errors (NoSuch*, NotFound, MissingParameter)
            if _is_expected_aws_error(e):
                logger.debug(f"Skipping retry for expected error: {e}")
                raise

            # Don't retry permanent errors (bad params, auth, unavailable endpoints)
            if _is_permanent_error(e):
                logger.debug(f"Skipping retry for permanent error: {type(e).__name__}: {str(e)[:120]}")
                raise

            # Check if this is a throttling error
            error_code = ''
            error_message = str(e).lower()
            if hasattr(e, 'response'):
                error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''

            is_throttling = (
                'ThrottlingException' in str(type(e).__name__) or
                'ThrottlingException' in error_code or
                'throttling' in error_message or
                'rate exceeded' in error_message
            )

            if attempt == MAX_RETRIES - 1:
                raise

            if is_throttling:
                delay = max(BASE_DELAY * 2, BASE_DELAY * (BACKOFF_FACTOR ** attempt) * 2)
                logger.debug(f"Throttling detected, using longer delay: {delay:.2f}s (attempt {attempt+1}/{MAX_RETRIES})")
            else:
                delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
                logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")

            sleep(delay)


def _call_with_timeout(client, action: str, params: Dict[str, Any], timeout: int = OPERATION_TIMEOUT) -> Dict[str, Any]:
    """
    Make API call with timeout protection for non-paginated operations.

    Args:
        client: Boto3 client
        action: API action name (camelCase or snake_case)
        params: API parameters
        timeout: Maximum time in seconds (default: OPERATION_TIMEOUT)

    Returns:
        API response dict

    Raises:
        TimeoutError: If operation exceeds timeout
    """
    action = _normalize_action(action)
    start_time = time.time()

    def _make_call():
        return _retry_call(getattr(client, action), **params)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_make_call)
            result = future.result(timeout=timeout)

            elapsed = time.time() - start_time
            if elapsed > 60:
                logger.info(f"Slow operation {action}: {elapsed:.1f}s")

            return result

    except FutureTimeoutError:
        elapsed = time.time() - start_time
        logger.error(f"{action} timed out after {timeout}s (elapsed: {elapsed:.1f}s)")
        raise TimeoutError(f"{action} exceeded {timeout}s timeout")


def _paginate_api_call(client, action: str, params: Dict[str, Any],
                       discovery_config: Optional[Dict] = None,
                       max_pages: int = 100,
                       operation_timeout: int = OPERATION_TIMEOUT) -> Dict[str, Any]:
    """
    Robust pagination with multiple safeguards against stuck cases.

    Uses boto3 paginators when available (AWS-recommended), with fallbacks.
    Includes timeout protection, circular token detection, and item limits.
    """
    action = _normalize_action(action)
    start_time = time.time()
    service_name = client.meta.service_model.service_name

    def _execute_pagination():
        # Layer 1: Check if boto3 paginator is available (most reliable)
        try:
            if client.can_paginate(action):
                paginator = client.get_paginator(action)

                has_max_results = any(k.lower() in ['maxresults', 'maxrecords', 'limit', 'maxitems']
                                     for k in params.keys())

                if not has_max_results:
                    if service_name == 'sagemaker':
                        default_page_size = 100
                    elif service_name in ['cognito-idp', 'cognito']:
                        default_page_size = 60
                    elif service_name == 'kafka':
                        default_page_size = 100
                    else:
                        default_page_size = 1000

                    params['MaxResults'] = default_page_size
                    logger.debug(f"Auto-added MaxResults={default_page_size} for {action} (service: {service_name})")

                page_size = params.get('MaxResults', 1000)
                pagination_config = {
                    'PageSize': min(page_size, 1000),
                    'MaxItems': None
                }

                page_params = {k: v for k, v in params.items()
                              if k not in ['MaxResults', 'MaxRecords', 'Limit', 'MaxItems']}

                page_iterator = paginator.paginate(**page_params, PaginationConfig=pagination_config)

                all_items = []
                result_array_key = None
                first_page = None
                page_count = 0
                seen_tokens = set()
                total_items = 0

                for page in page_iterator:
                    if first_page is None:
                        first_page = page
                        for key, value in page.items():
                            if isinstance(value, list) and key not in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                                result_array_key = key
                                all_items.extend(value)
                                total_items += len(value)
                                break
                    else:
                        if result_array_key and result_array_key in page:
                            items = page[result_array_key]
                            all_items.extend(items)
                            total_items += len(items)

                    current_token = page.get('NextToken') or page.get('Marker')
                    if current_token:
                        if current_token in seen_tokens:
                            logger.error(f"Circular pagination token detected for {action} - breaking")
                            break
                        seen_tokens.add(current_token)

                    page_count += 1
                    if page_count >= max_pages:
                        logger.error(f"Hit max pages limit ({max_pages}) for {action} - possible infinite loop")
                        break

                    if total_items > MAX_ITEMS_PER_DISCOVERY:
                        logger.warning(
                            f"{action} returned {total_items} items (limit: {MAX_ITEMS_PER_DISCOVERY}). "
                            f"Consider using Filters to reduce result set."
                        )
                        break

                if first_page and result_array_key:
                    combined = first_page.copy()
                    combined[result_array_key] = all_items
                    for token in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                        combined.pop(token, None)

                    if page_count > 1:
                        logger.debug(f"Paginated {action}: {page_count} pages, {total_items} items")
                    return combined

                return first_page if first_page else {}

        except (ValueError, AttributeError) as e:
            logger.debug(f"Paginator not available for {action}: {e}")

            # Layer 2: Try manual pagination
            first_response = _retry_call(getattr(client, action), **params)

            pagination_tokens = ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']
            has_token = any(token in first_response for token in pagination_tokens)

            if not has_token:
                return first_response

            return _manual_paginate_with_token(client, action, params, first_response, max_pages)

        except Exception as e:
            logger.debug(f"Pagination error for {action}, using single call: {e}")
            return _call_with_timeout(client, action, params, timeout=300)

    # Execute with operation-level timeout
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute_pagination)
            result = future.result(timeout=operation_timeout)

            elapsed = time.time() - start_time
            if elapsed > 300:
                logger.warning(
                    f"{action} took {elapsed/60:.1f} minutes. "
                    f"Consider optimizing with Filters or reducing scope."
                )

            return result

    except FutureTimeoutError:
        elapsed = time.time() - start_time
        logger.error(
            f"{action} exceeded {operation_timeout}s timeout after {elapsed:.1f}s. "
            f"This operation may be stuck or returning too many results."
        )
        raise TimeoutError(f"{action} exceeded {operation_timeout}s timeout")


def _manual_paginate_with_token(client, action: str, params: Dict[str, Any],
                                first_response: Dict[str, Any], max_pages: int = 100) -> Dict[str, Any]:
    """
    Manual pagination using NextToken/Marker tokens.

    Args:
        client: Boto3 client
        action: API action name
        params: API parameters
        first_response: First page response
        max_pages: Maximum pages to fetch

    Returns:
        Combined response with all pages
    """
    pagination_tokens = ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']
    result_arrays = ['Snapshots', 'Images', 'Volumes', 'Instances', 'Buckets',
                     'Policies', 'Roles', 'Users', 'Groups', 'Functions', 'Tables',
                     'Queues', 'Topics', 'Subscriptions', 'Clusters', 'Streams',
                     'Keys', 'Aliases', 'Grants', 'Secrets', 'Domains', 'Zones',
                     'Distributions', 'Items', 'Results', 'Resources']

    # Find result array
    result_array_key = None
    for key in result_arrays:
        if key in first_response and isinstance(first_response[key], list):
            result_array_key = key
            break

    if not result_array_key:
        for key, value in first_response.items():
            if isinstance(value, list) and key not in pagination_tokens:
                result_array_key = key
                break

    if not result_array_key:
        return first_response

    all_items = list(first_response[result_array_key])
    seen_tokens = set()
    page_count = 0
    original_params = params.copy()

    # Find pagination token
    token_field = None
    next_token = None
    for token_key in pagination_tokens:
        if token_key in first_response and first_response[token_key]:
            next_token = first_response[token_key]
            token_field = token_key
            break

    # Paginate
    while next_token and page_count < max_pages:
        if next_token in seen_tokens:
            logger.error(f"Circular pagination token detected for {action} - breaking")
            break
        seen_tokens.add(next_token)

        page_params = original_params.copy()
        page_params[token_field] = next_token

        try:
            page_response = _retry_call(getattr(client, action), **page_params)

            if result_array_key in page_response:
                all_items.extend(page_response[result_array_key])

            next_token = page_response.get(token_field)
            page_count += 1

            if not next_token:
                break

        except Exception as e:
            logger.warning(f"Pagination stopped at page {page_count + 1} for {action}: {e}")
            break

    combined = first_response.copy()
    combined[result_array_key] = all_items
    for token_key in pagination_tokens:
        combined.pop(token_key, None)

    if page_count > 0:
        logger.debug(f"Manual pagination {action}: {page_count + 1} pages, {len(all_items)} items")

    return combined
