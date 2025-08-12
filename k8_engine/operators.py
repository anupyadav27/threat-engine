import re
from typing import Any


def evaluate_field_condition(actual: Any, operator: str = None, expected: Any = None) -> bool:
    op = (operator or 'exists').lower()

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

    # default safe fallback
    return False 