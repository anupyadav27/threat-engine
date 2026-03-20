"""
Condition evaluation and template resolution for AWS discovery checks.

Extracted from service_scanner.py for maintainability.
"""
import logging
import re
from typing import Any, Dict

from .extraction import extract_value

logger = logging.getLogger('compliance-boto3')


def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate a condition with the given operator and expected value

    Supported operators:
    - exists, not_exists: Check if value exists/doesn't exist
    - equals, not_equals: Equality checks
    - gt, gte, lt, lte: Numeric comparisons
    - contains, not_contains: List/string membership
    - in, not_in: Value in/not in list (for enum checks)
    - is_empty, not_empty: Empty checks
    - length_gte, length_gt, length_lt, length_lte: Length comparisons
    """
    # Existence checks
    if operator == 'exists':
        return value is not None and value != '' and value != []
    elif operator == 'not_exists':
        return value is None or value == '' or value == []
    elif operator == 'is_empty':
        return value is None or value == '' or value == []
    elif operator == 'not_empty':
        return value is not None and value != '' and value != []

    # Equality checks
    elif operator == 'equals':
        return value == expected
    elif operator == 'not_equals':
        return value != expected

    # Numeric comparisons
    elif operator == 'gt':
        try:
            return float(value) > float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'gte':
        try:
            return float(value) >= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'lt':
        try:
            return float(value) < float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'lte':
        try:
            return float(value) <= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False

    # List/string membership
    elif operator == 'contains':
        if isinstance(value, (list, str)):
            return expected in value
        return False
    elif operator == 'not_contains':
        if isinstance(value, (list, str)):
            return expected not in value
        return False

    # Enum/list membership (value in/not in expected list)
    elif operator == 'in':
        if isinstance(expected, list):
            return value in expected
        return False
    elif operator == 'not_in':
        if isinstance(expected, list):
            return value not in expected
        return False

    # Length comparisons
    elif operator == 'length_gte':
        if isinstance(value, (list, str)):
            try:
                return len(value) >= int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_gt':
        if isinstance(value, (list, str)):
            try:
                return len(value) > int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_lt':
        if isinstance(value, (list, str)):
            try:
                return len(value) < int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_lte':
        if isinstance(value, (list, str)):
            try:
                return len(value) <= int(expected)
            except (ValueError, TypeError):
                return False
        return False

    # Operator aliases (for backward compatibility)
    elif operator == 'greater_than':
        try:
            return float(value) > float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'less_than':
        try:
            return float(value) < float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'greater_than_or_equal':
        try:
            return float(value) >= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'less_than_or_equal':
        try:
            return float(value) <= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False

    else:
        logger.warning(f"Unknown operator: {operator}")
        return False

def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """Resolve template variables like {{ variable }} in text"""
    if not isinstance(text, str) or '{{' not in text:
        return text

    def replace_var(match):
        var_path = match.group(1).strip()

        # Handle special functions
        if var_path.startswith('exists('):
            path = var_path[7:-1]  # Remove 'exists(' and ')'
            value = extract_value(context, path)
            exists_result = value is not None and value != '' and value != []
            return str(exists_result)

        # Handle complex expressions with dynamic keys like user_details[u.UserName].User.PasswordLastUsed
        if '[' in var_path and ']' in var_path:
            # Find the dynamic key part like [u.UserName]
            start_bracket = var_path.find('[')
            end_bracket = var_path.find(']')
            if start_bracket != -1 and end_bracket != -1:
                # Extract the base path and dynamic key
                base_path = var_path[:start_bracket]
                dynamic_key_expr = var_path[start_bracket+1:end_bracket]
                remaining_path = var_path[end_bracket+1:]

                # Resolve the dynamic key (e.g., u.UserName)
                if '.' in dynamic_key_expr and not dynamic_key_expr.startswith('{{'):
                    dynamic_key = extract_value(context, dynamic_key_expr)
                else:
                    dynamic_key = resolve_template(dynamic_key_expr, context)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Dynamic key expression: %s -> %s", dynamic_key_expr, dynamic_key)

                if '.' in dynamic_key:
                    full_key = base_path
                else:
                    full_key = f"{base_path}.{dynamic_key}"

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Complex template: %s -> %s", var_path, full_key)
                if full_key in context:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Full key %s exists in context", full_key)
                    if remaining_path:
                        remaining_path_clean = remaining_path.lstrip('.')
                        remaining_path_clean = remaining_path_clean.replace('[', '').replace(']', '')
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug("Extracting from %s with path: %s", full_key, remaining_path_clean)
                        value = extract_value(context[full_key], remaining_path_clean)
                    else:
                        value = context[full_key]
                else:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Full key %s not found in context (keys=%s)", full_key, list(context.keys()))
                    value = None

                # Handle nested access for complex keys
                if '.' in dynamic_key and full_key in context:
                    full_path = f"{dynamic_key}.{remaining_path_clean}" if remaining_path else dynamic_key
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Extracting from %s with nested path: %s", full_key, full_path)
                    value = extract_value(context[full_key], full_path)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Complex template result: %s", value)
                return str(value) if value is not None else ''

        # Debug logging (guarded to avoid expensive stringification at INFO level)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Resolving template variable: %s", var_path)
            logger.debug("Context keys: %s", list(context.keys()))
            if 'u' in context:
                logger.debug("Context 'u' object present")

        value = extract_value(context, var_path)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Extracted value: %s", value)

        # Return as string, but preserve numeric strings for account IDs
        if value is not None:
            if isinstance(value, list) and len(value) == 0:
                return ''
            if isinstance(value, (int, float)):
                return str(value)
            if isinstance(value, list):
                if len(value) == 1:
                    return str(value[0])
                return str(value)
            return str(value)
        return ''

    resolved = re.sub(r'\{\{\s*([^}]+)\s*\}\}', replace_var, text)

    # For account IDs and similar numeric strings that should stay as strings
    if 'Account' in text or 'AccountId' in text or 'account_id' in text:
        return resolved

    # Try to convert to appropriate type
    if resolved.isdigit():
        return int(resolved)
    elif resolved.replace('.', '', 1).isdigit():
        return float(resolved)
    elif resolved.lower() in ('true', 'false'):
        return resolved.lower() == 'true'

    return resolved
