"""
python_to_yaml_generator.py — Phase 1 Golden-Check Framework

Provides:
  extract_value(obj, path)          — navigate nested dicts/lists using dot
                                       notation + [] array expansion
  evaluate_condition(value, op, expected) — single predicate (mirrors engine)
  evaluate_conditions(item, conditions)   — full conditions-dict evaluation
  run_spec(spec, items)             — batch-evaluate a CheckSpec against a list
  emit_yaml(spec)                   — render a CheckSpec as YAML string
  GoldenCheck                       — dataclass for one golden-set entry
  run_golden(gc)                    — run a GoldenCheck and print results

Condition dict formats (same as catalog/rule/):

  Single:
    {"var": "item.field.path", "op": "exists"}
    {"var": "item.field", "op": "equals", "value": "ACTIVE"}

  AND-all:
    {"all": [{"var": "...", "op": "..."}, ...]}

  OR-any:
    {"any": [{"var": "...", "op": "..."}, ...]}
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from typing import Any

import yaml

# Matches key[N]  e.g. "Rules[0]", "containers[2]"
_BRACKET_IDX = re.compile(r'^(\w+)\[(\d+)\]$')


# ══════════════════════════════════════════════════════════════════════════════
# Field extractor  (mirrors service_scanner.extract_value)
# ══════════════════════════════════════════════════════════════════════════════

def extract_value(obj: Any, path: str) -> Any:
    """Navigate a nested dict/list using dot-path with optional [] expansion.

    Patterns:
      item.Name              → simple key lookup
      item.Config.Enabled    → nested key lookup
      item.Rules[0].Algo     → numeric index access
      item.Rules[].Algo      → collect Algo from every element in Rules
    """
    if obj is None:
        return None

    # Strip leading "item." prefix — the conditions use "item.X" but the
    # caller passes the raw resource dict (i.e. item itself), not a wrapper.
    if path.startswith("item."):
        path = path[len("item."):]

    parts = path.split(".")
    current = obj

    for idx, part in enumerate(parts):
        if current is None:
            return None

        # Numeric index: Rules.0 or inside array traversal
        if isinstance(current, list) and part.isdigit():
            i = int(part)
            current = current[i] if 0 <= i < len(current) else None
            continue

        # key[N] inline index: "Rules[0]", "containers[1]"
        m = _BRACKET_IDX.match(part)
        if m:
            key, i = m.group(1), int(m.group(2))
            arr = current.get(key, []) if isinstance(current, dict) else []
            current = arr[i] if isinstance(arr, list) and 0 <= i < len(arr) else None
            continue

        # Array expansion: Rules[]
        if part.endswith("[]"):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            rest = ".".join(parts[idx + 1:])
            if not rest:
                current = arr
            else:
                result: list = []
                for elem in arr:
                    sub = extract_value(elem, rest)
                    if isinstance(sub, list):
                        result.extend(sub)
                    elif sub is not None:
                        result.append(sub)
                current = result
            break  # rest already consumed

        # Normal key lookup
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            # Implicit fan-out: collect from every element
            rest = ".".join(parts[idx:])
            result = []
            for elem in current:
                sub = extract_value(elem, rest)
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        else:
            return None

    return current


# ══════════════════════════════════════════════════════════════════════════════
# Single-condition evaluator  (mirrors service_scanner.evaluate_condition)
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_condition(value: Any, op: str, expected: Any = None) -> bool:
    """Evaluate one predicate. op must be a recognised operator string."""

    # Existence / emptiness
    if op in ("exists", "not_empty", "is_not_null"):
        return value is not None and value != "" and value != [] and value != {}
    if op in ("not_exists", "is_empty", "is_null"):
        return value is None or value == "" or value == [] or value == {}

    # Boolean convenience
    if op in ("is_true",):
        return value is True or str(value).lower() == "true"
    if op in ("is_false",):
        return value is False or str(value).lower() == "false"

    # Equality
    if op in ("equals", "eq"):
        # Support string "true"/"false" compared against bool
        if isinstance(value, bool) and isinstance(expected, str):
            return value == (expected.lower() == "true")
        if isinstance(expected, bool) and isinstance(value, str):
            return expected == (value.lower() == "true")
        return value == expected
    if op in ("not_equals", "ne"):
        if isinstance(value, bool) and isinstance(expected, str):
            return value != (expected.lower() == "true")
        return value != expected

    # Numeric comparisons
    def _num(v: Any, e: Any) -> tuple[float, float] | None:
        try:
            return float(v), float(e)
        except (ValueError, TypeError):
            return None

    if op in ("gt", "greater_than"):
        r = _num(value, expected)
        return r[0] > r[1] if r else False
    if op in ("gte", "greater_than_or_equal"):
        r = _num(value, expected)
        return r[0] >= r[1] if r else False
    if op in ("lt", "less_than"):
        r = _num(value, expected)
        return r[0] < r[1] if r else False
    if op in ("lte", "less_than_or_equal"):
        r = _num(value, expected)
        return r[0] <= r[1] if r else False

    # Membership
    if op == "contains":
        return expected in value if isinstance(value, (list, str)) else False
    if op == "not_contains":
        return expected not in value if isinstance(value, (list, str)) else True
    if op == "in":
        return value in expected if isinstance(expected, list) else False
    if op == "not_in":
        return value not in expected if isinstance(expected, list) else True

    # Length comparisons
    if op == "length_gte":
        return len(value) >= int(expected) if hasattr(value, "__len__") else False
    if op == "length_gt":
        return len(value) > int(expected) if hasattr(value, "__len__") else False
    if op == "length_lte":
        return len(value) <= int(expected) if hasattr(value, "__len__") else False
    if op == "length_lt":
        return len(value) < int(expected) if hasattr(value, "__len__") else False
    if op == "length_equals":
        return len(value) == int(expected) if hasattr(value, "__len__") else False

    raise ValueError(f"Unknown operator: {op!r}")


# ══════════════════════════════════════════════════════════════════════════════
# Full conditions-dict evaluator
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_conditions(item: dict, conditions: dict) -> bool:
    """Recursively evaluate a conditions dict against an item.

    Handles:
      - Single condition:  {"var": "item.X", "op": "...", ["value": ...]}
      - AND compound:      {"all": [...]}
      - OR compound:       {"any": [...]}
      - NOT compound:      {"not": {...}}
    """
    if not conditions:
        return True

    if "all" in conditions:
        return all(evaluate_conditions(item, c) for c in conditions["all"])

    if "any" in conditions:
        return any(evaluate_conditions(item, c) for c in conditions["any"])

    if "not" in conditions:
        return not evaluate_conditions(item, conditions["not"])

    # Single predicate
    var = conditions.get("var", "")
    op  = conditions.get("op", "")
    expected = conditions.get("value")

    if not var or not op:
        raise ValueError(f"Conditions entry missing 'var' or 'op': {conditions}")

    value = extract_value(item, var)
    return evaluate_condition(value, op, expected)


# ══════════════════════════════════════════════════════════════════════════════
# Check spec runner
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckSpec:
    rule_id: str
    for_each: str
    severity: str
    conditions: dict
    pattern: str = ""       # e.g. "scalar-exists", "array-any", "multi-all"


def run_spec(spec: CheckSpec, items: list[dict]) -> list[dict]:
    """Evaluate spec.conditions against every item. Returns list of result dicts."""
    results = []
    for item in items:
        passed = evaluate_conditions(item, spec.conditions)
        results.append({
            "rule_id": spec.rule_id,
            "result": "PASS" if passed else "FAIL",
            "item": item,
        })
    return results


# ══════════════════════════════════════════════════════════════════════════════
# YAML emitter
# ══════════════════════════════════════════════════════════════════════════════

def emit_yaml(spec: CheckSpec) -> str:
    """Render a CheckSpec as a check-engine YAML string."""
    doc = {
        "version": "1.0",
        "rule_id": spec.rule_id,
        "for_each": spec.for_each,
        "severity": spec.severity,
        "conditions": spec.conditions,
    }
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=120)


# ══════════════════════════════════════════════════════════════════════════════
# Golden-check runner
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class GoldenCheck:
    spec: CheckSpec
    fixture_pass: dict                      # must → PASS
    fixture_fail: dict                      # must → FAIL
    description: str = ""
    extra_notes: str = ""


def run_golden(gc: GoldenCheck, verbose: bool = True) -> bool:
    """Run a GoldenCheck. Returns True if both assertions hold."""
    ok_pass = evaluate_conditions(gc.fixture_pass, gc.spec.conditions)
    ok_fail = evaluate_conditions(gc.fixture_fail, gc.spec.conditions)

    passed = ok_pass and not ok_fail

    if verbose:
        mark = "✓" if passed else "✗"
        print(f"  [{mark}] {gc.spec.rule_id}  ({gc.spec.pattern})")
        if not ok_pass:
            print(f"       FAIL: fixture_pass did not PASS — check your conditions or fixture")
        if ok_fail:
            print(f"       FAIL: fixture_fail did not FAIL — condition too permissive")

    return passed
