import re
from typing import Any, List


def evaluate_field_condition(actual: Any, operator: str = None, expected: Any = None) -> bool:
    """
    Evaluate a field condition with various operators.
    Supports list iteration with 'all_' and 'any_' prefixes.
    """
    op = (operator or 'exists').lower()

    # Handle list iteration operators (all_* and any_*)
    if op.startswith('all_') or op.startswith('any_'):
        if not isinstance(actual, list):
            # If not a list, treat as single item
            actual = [actual] if actual is not None else []
        
        base_op = op[4:] if op.startswith('all_') else op[4:]  # Remove 'all_' or 'any_' prefix
        results = [evaluate_field_condition(item, base_op, expected) for item in actual]
        
        if op.startswith('all_'):
            return all(results) if results else False
        else:  # any_
            return any(results) if results else False

    if op == 'exists':
        return actual is not None
    if op == 'not_exists':
        return actual is None

    if op in ('equals', 'eq'):
        return actual == expected
    if op in ('not_equals', 'ne'):
        return actual != expected

    if op in ('gte', 'ge'):
        try:
            return float(actual) >= float(expected)
        except Exception:
            return False
    if op in ('lte', 'le'):
        try:
            return float(actual) <= float(expected)
        except Exception:
            return False
    if op in ('gt',):
        try:
            return float(actual) > float(expected)
        except Exception:
            return False
    if op in ('lt',):
        try:
            return float(actual) < float(expected)
        except Exception:
            return False

    if op == 'contains':
        try:
            return expected in actual
        except Exception:
            return False
    if op == 'not_contains':
        try:
            return expected not in actual
        except Exception:
            # If membership check fails, treat as not contained
            return True

    if op == 'regex':
        try:
            return re.search(str(expected), str(actual)) is not None
        except Exception:
            return False
    if op == 'not_regex':
        try:
            return re.search(str(expected), str(actual)) is None
        except Exception:
            # If regex fails, treat as not matched
            return True
    
    if op == 'is_empty':
        if isinstance(actual, (list, dict, str)):
            return len(actual) == 0
        return actual is None
    
    if op == 'not_empty':
        if isinstance(actual, (list, dict, str)):
            return len(actual) > 0
        return actual is not None

    # default safe fallback
    return False 