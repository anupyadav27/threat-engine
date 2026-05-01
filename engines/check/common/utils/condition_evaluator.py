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
from datetime import datetime, timezone
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


def field_exists(obj: Any, path: str) -> bool:
    """
    Return True if the terminal key in *path* is present in the nested object,
    regardless of its value — including when the value is None.

    Unlike extract_value(), which returns None for BOTH "key missing" and
    "key present with None value", this function distinguishes the two cases:

      field_exists({"Email": None}, "Email")        → True   (key present)
      field_exists({},              "Email")        → False  (key absent)
      field_exists({"a": {}},      "a.b")           → False  (terminal missing)
      field_exists({"a": {"b": None}}, "a.b")       → True   (terminal present)

    Used by check_engine to decide whether NOT_APPLICABLE is warranted.
    """
    if obj is None or not path:
        return False

    parts = path.split(".")
    terminal_key = parts[-1]

    if len(parts) == 1:
        if isinstance(obj, dict):
            return terminal_key in obj
        if isinstance(obj, list):
            return any(isinstance(i, dict) and terminal_key in i for i in obj)
        return False

    # Navigate to the parent of the terminal key using extract_value.
    # extract_value returns None when any intermediate key is missing OR when
    # an intermediate value is None — both cases correctly mean "terminal can't exist".
    parent = extract_value(obj, ".".join(parts[:-1]))

    if parent is None:
        return False
    if isinstance(parent, dict):
        return terminal_key in parent
    if isinstance(parent, list):
        return any(isinstance(i, dict) and terminal_key in i for i in parent)
    return False


# ---------------------------------------------------------------------------
# evaluate_condition
# ---------------------------------------------------------------------------

def _parse_datetime(value: Any) -> datetime | None:
    """Parse a datetime string or epoch into a timezone-aware datetime. Returns None on failure."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    s = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


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
      age_days / within_days  (date-age operators: compare days since timestamp)
    """
    if operator == "exists":
        return value is not None and value != "" and value != []
    if operator == "not_exists":
        return value is None or value == "" or value == []
    if operator == "is_empty":
        return value is None or value == "" or value == []
    if operator in ("not_empty", "is_not_empty"):
        return value is not None and value != "" and value != []
    if operator in ("is_true", "is_truthy"):
        return bool(value) if value is not None else False
    if operator in ("is_false", "is_falsy"):
        # None is falsy → not bool(None) = True → PASS for absent boolean fields.
        # This correctly handles cases like spec.hostNetwork absent (= disabled = safe).
        return not bool(value)

    if operator in ("equals", "not_equals"):
        # Normalize bool/string mismatch: 'true'/'false' strings ↔ booleans
        # Check rules often store value: 'true' (YAML string); DB returns Python bool True
        v, e = value, expected
        if isinstance(e, str) and e.lower() in ("true", "false"):
            e = e.lower() == "true"
        if isinstance(v, str) and v.lower() in ("true", "false"):
            v = v.lower() == "true"
        return (v == e) if operator == "equals" else (v != e)

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

    # Multi-prefix operators (CIEM log rules)
    # starts_with_any: True if value starts with ANY prefix in expected list
    if operator == "starts_with_any":
        if not isinstance(value, str):
            return False
        prefixes = expected if isinstance(expected, list) else [str(expected)]
        return any(value.startswith(str(p)) for p in prefixes)

    # not_starts_with: True if value does NOT start with expected (string or any in list)
    if operator == "not_starts_with":
        if not isinstance(value, str):
            return True
        prefixes = expected if isinstance(expected, list) else [str(expected)]
        return not any(value.startswith(str(p)) for p in prefixes)

    # Date-age operators: compare days elapsed since the timestamp in value
    # age_days: True if age (days since timestamp) <= expected  (i.e. rotated recently enough)
    # within_days: synonym for age_days
    if operator in ("age_days", "within_days"):
        dt = _parse_datetime(value)
        if dt is None:
            return False
        try:
            threshold = int(expected)
        except (ValueError, TypeError):
            return False
        age = (datetime.now(tz=timezone.utc) - dt).days
        return age <= threshold

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
