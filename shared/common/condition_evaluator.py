"""
Condition Evaluator — CSP-agnostic rule condition evaluation

Extracted from engine_check_aws/engine/service_scanner.py so that the
common orchestration layer has no dependency on the old engine/ package.

Functions:
  extract_value(obj, path)             — dot-notation path traversal
  evaluate_condition(value, op, expected) — 30+ operators
  resolve_template(text, context)      — {{ variable }} template resolution
"""

import re
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# extract_value
# ---------------------------------------------------------------------------

def extract_value(obj: Any, path: str) -> Any:
    """
    Extract a value from a nested object using dot-notation and array syntax.

    Supports:
      - Simple paths:  'item.Bucket.Name'
      - Array index:   'item.Tags.0.Key'
      - Array flatten: 'item.Tags[].Key'  (returns list)
    """
    if obj is None or not path:
        return None

    parts = path.split(".")
    current = obj

    for idx, part in enumerate(parts):
        if current is None:
            return None

        # Numeric array index
        if isinstance(current, list) and part.isdigit():
            i = int(part)
            current = current[i] if 0 <= i < len(current) else None

        # Array-flatten operator: key[]
        elif part.endswith("[]"):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            remaining = parts[idx + 1:]
            if not remaining:
                return arr
            result = []
            for item in arr:
                sub = extract_value(item, ".".join(remaining))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result

        # Current is a list — fan out to each element
        elif isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, ".".join(parts[idx:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result

        # Dict key lookup
        elif isinstance(current, dict):
            current = current.get(part)

        else:
            return None

    return current


# ---------------------------------------------------------------------------
# evaluate_condition
# ---------------------------------------------------------------------------

def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """
    Evaluate a single condition.

    Supported operators (aliases included for backward-compatibility):
      exists / not_exists / is_empty / not_empty
      equals / not_equals
      gt / gte / lt / lte  (also: greater_than / less_than / …)
      contains / not_contains
      in / not_in
      length_gte / length_gt / length_lt / length_lte
    """
    if operator == "exists":
        return value is not None and value != "" and value != []
    if operator == "not_exists":
        return value is None or value == "" or value == []
    if operator == "is_empty":
        return value is None or value == "" or value == []
    if operator in ("not_empty", "is_not_empty"):
        return value is not None and value != "" and value != []

    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected

    # Numeric comparisons
    def _num(a, b):
        return float(a), float(b)

    for op_str, fn in (
        ("gt", lambda a, b: a > b),
        ("gte", lambda a, b: a >= b),
        ("lt", lambda a, b: a < b),
        ("lte", lambda a, b: a <= b),
        ("greater_than", lambda a, b: a > b),
        ("less_than", lambda a, b: a < b),
        ("greater_than_or_equal", lambda a, b: a >= b),
        ("less_than_or_equal", lambda a, b: a <= b),
    ):
        if operator == op_str:
            try:
                a, b = _num(value, expected)
                return fn(a, b)
            except (ValueError, TypeError):
                return False

    if operator == "contains":
        return expected in value if isinstance(value, (list, str)) else False
    if operator == "not_contains":
        return expected not in value if isinstance(value, (list, str)) else False

    if operator == "in":
        return value in expected if isinstance(expected, list) else False
    if operator == "not_in":
        return value not in expected if isinstance(expected, list) else False

    # Length comparisons
    for op_str, fn in (
        ("length_gte", lambda l, n: l >= n),
        ("length_gt",  lambda l, n: l > n),
        ("length_lt",  lambda l, n: l < n),
        ("length_lte", lambda l, n: l <= n),
    ):
        if operator == op_str:
            if isinstance(value, (list, str)):
                try:
                    return fn(len(value), int(expected))
                except (ValueError, TypeError):
                    return False
            return False

    if operator in ("starts_with",):
        return isinstance(value, str) and value.startswith(str(expected))
    if operator in ("ends_with",):
        return isinstance(value, str) and value.endswith(str(expected))

    logger.warning("Unknown operator: %s", operator)
    return False


# ---------------------------------------------------------------------------
# resolve_template
# ---------------------------------------------------------------------------

def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """
    Resolve {{ variable }} template expressions in a string.

    Supports:
      - Simple paths:    {{ item.FieldName }}
      - exists() check:  {{ exists(item.FieldName) }}

    Returns the resolved string, or bool/int if the full string is a template
    that resolves to a primitive.
    """
    if not isinstance(text, str) or "{{" not in text:
        return text

    def _replace(match: re.Match) -> str:
        expr = match.group(1).strip()

        # exists(...) function
        if expr.startswith("exists(") and expr.endswith(")"):
            path = expr[7:-1]
            val = extract_value(context, path)
            exists = val is not None and val != "" and val != []
            return str(exists)

        # Simple path
        val = extract_value(context, expr)
        return str(val) if val is not None else ""

    result = re.sub(r"\{\{\s*(.*?)\s*\}\}", _replace, text)

    # Coerce to bool / int when the entire string was a single template
    if result.lower() == "true":
        return True
    if result.lower() == "false":
        return False
    try:
        return int(result)
    except (ValueError, TypeError):
        pass
    return result
