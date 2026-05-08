#!/usr/bin/env python3
"""
Jinja2-based check-rule YAML renderer for CIS Technology compliance rules.

Renders a check rule YAML string for a single (tech, section) group containing
both automated and manual controls.

Usage::

    from catalog.rule.tech_templates.render_check import render_check_rules

    yaml_str = render_check_rules(
        tech="postgresql",
        category="database",
        section="6",
        rows=classified_rows,
    )
"""

import re
import sys
from pathlib import Path

# ─── Jinja2 import ────────────────────────────────────────────────────────────

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "jinja2 is required for render_check.  Install it: pip install jinja2"
    ) from exc

# ─── Utility imports ──────────────────────────────────────────────────────────

_BASE = Path("/Users/apple/Desktop/threat-engine")
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from catalog.rule.tech_rule_utils import (  # noqa: E402
    make_discovery_id,
    make_rule_id,
    make_slug,
    section_to_slug,
    tech_display_name,
)

# ─── Template directory ───────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent
_TEMPLATE_FILE = "check_rule.yaml.j2"

# ─── Severity normalisation ───────────────────────────────────────────────────

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
}


def _normalise_severity(raw: str) -> str:
    """Normalise raw severity to lowercase; map unknowns to 'informational'.

    Args:
        raw: Raw severity string (e.g. ``"HIGH"``, ``"CRITICAL"``).

    Returns:
        A lowercase severity string, one of: critical, high, medium, low,
        informational.
    """
    lower = raw.strip().lower()
    return _SEVERITY_MAP.get(lower, "informational")


# ─── Assertion derivation heuristics ─────────────────────────────────────────


def _derive_assertion_field(row: dict) -> str:
    """Derive the assertion field name from the row title / description.

    Args:
        row: Augmented row dict.

    Returns:
        An assertion field string such as ``"value"``, ``"enabled"``,
        ``"row_count"``, ``"length"``, ``"version"``, or ``"port"``.
    """
    combined = (row.get("title", "") + " " + row.get("description", "")).lower()

    if "count" in combined or "number of" in combined:
        return "row_count"
    if "enabled" in combined or "disabled" in combined:
        return "enabled"
    if "length" in combined or "minimum" in combined:
        return "length"
    if "version" in combined:
        return "version"
    if "port" in combined:
        return "port"

    return "value"


def _derive_assertion_operator(row: dict) -> str:
    """Derive the assertion operator from the row title / description.

    Args:
        row: Augmented row dict.

    Returns:
        An operator string: ``"equals"``, ``"gte"``, ``"lte"``,
        ``"not_equals"``, or ``"exists"``.
    """
    combined = (row.get("title", "") + " " + row.get("description", "")).lower()

    if any(kw in combined for kw in ("at least", "minimum", "not less")):
        return "gte"
    if any(kw in combined for kw in ("at most", "maximum", "not more")):
        return "lte"
    if any(kw in combined for kw in ("not equal", "must not")):
        return "not_equals"
    if any(kw in combined for kw in ("exists", "configured")):
        return "exists"

    return "equals"


# Known specific expected values to detect in audit_procedure
_KNOWN_EXPECTED_VALUES: list[tuple[str, str]] = [
    ("scram-sha-256", "scram-sha-256"),
    ("scram_sha_256", "scram-sha-256"),
    (r"\bon\b", "on"),
    (r"\boff\b", "off"),
    (r"\byes\b", "yes"),
    (r"\bno\b", "no"),
]

# Digit patterns like "14 characters", "90 days"
_DIGIT_IN_TITLE = re.compile(r"\b(\d+)\s*(?:character|char|day|minute|hour|second|byte)", re.IGNORECASE)


def _derive_assertion_expected(row: dict) -> str:
    """Derive the expected assertion value from the row.

    Args:
        row: Augmented row dict.

    Returns:
        A string representing the expected value.
    """
    title = row.get("title", "").lower()
    description = row.get("description", "").lower()
    audit_proc = row.get("audit_procedure", "").lower()

    combined_title_desc = title + " " + description

    # Disabled → false
    if "disabled" in combined_title_desc:
        return "false"

    # Digit detected in title → numeric value
    m = _DIGIT_IN_TITLE.search(title)
    if m:
        return m.group(1)

    # Check audit_procedure for known specific values
    for pattern, value in _KNOWN_EXPECTED_VALUES:
        if re.search(pattern, audit_proc, re.IGNORECASE):
            return value

    # Enabled → true
    if "enabled" in combined_title_desc:
        return "true"

    return "true"


# ─── Version extraction ───────────────────────────────────────────────────────

_TECH_PREFIX_PATTERN = re.compile(r"^[a-z0-9_]+\s*_?\s*", re.IGNORECASE)


def _extract_version(framework_version: str, tech: str) -> str:
    """Extract a clean version string from the raw ``framework_version`` column.

    Strips a leading tech name prefix if present.  E.g. ``"17_v1.0.0"`` →
    ``"17 v1.0.0"``, ``"v1.1.0"`` → ``"v1.1.0"``.

    Args:
        framework_version: Raw framework_version cell value.
        tech: Technology key (used to strip leading prefix).

    Returns:
        A clean version string.
    """
    v = framework_version.strip()
    if not v:
        return "v1.0.0"

    # If it starts with the tech name, strip it
    tech_prefix = re.escape(tech.replace("_", r"[_\s]?"))
    cleaned = re.sub(r"^" + tech_prefix + r"\s*_?\s*", "", v, flags=re.IGNORECASE)

    # Replace underscores used as version separators with spaces
    # e.g. "17_v1.0.0" → "17 v1.0.0"
    cleaned = re.sub(r"_+", " ", cleaned).strip()

    return cleaned if cleaned else v


# ─── Row augmentation ─────────────────────────────────────────────────────────


def _augment_rows(
    rows: list,
    tech: str,
    section_slug: str,
    section: str,
) -> list[dict]:
    """Add computed ``_*`` fields to each row for use in the check rule template.

    Accepts rows that are either plain ``dict`` instances or ``ClassifiedRow``
    named-tuples (in which case the ``.row`` attribute is used).

    Args:
        rows: CSV row dicts or ClassifiedRow items for this (tech, section).
        tech: Technology key.
        section_slug: e.g. ``"section_6"``.
        section: Raw section string, e.g. ``"6"``.

    Returns:
        List of augmented dicts.
    """
    augmented: list[dict] = []
    for r in rows:
        row: dict = r.row if hasattr(r, "row") else dict(r)

        title = row.get("title", "").strip()
        try:
            check_slug = make_slug(title)
        except ValueError:
            check_slug = "unknown"

        row["_rule_id"] = make_rule_id(tech, section, check_slug)
        row["_scope"] = make_discovery_id(tech, section_slug, check_slug)
        row["_assertion_field"] = _derive_assertion_field(row)
        row["_assertion_operator"] = _derive_assertion_operator(row)
        row["_assertion_expected"] = _derive_assertion_expected(row)

        augmented.append(row)

    return augmented


# ─── Public render API ────────────────────────────────────────────────────────


def render_check_rules(
    tech: str,
    category: str,
    section: str,
    rows: list,
    section_slug: str = "",
) -> str:
    """Render the check rule YAML string for the given technology and section.

    ``automated_config`` rows produce entries with an ``assertion`` block.
    ``manual`` rows produce entries with a ``manual_procedure`` block only.

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        category: Benchmark category, e.g. ``"database"``.
        section: Raw CIS section string, e.g. ``"6"`` or ``"1.2"``.
        rows: CSV row dicts or ClassifiedRow items for this (tech, section).
            May include both automated and manual rows.
        section_slug: Pre-computed section slug.  Derived from *section* when
            empty (the default).

    Returns:
        Rendered YAML string.
    """
    if not section_slug:
        section_slug = section_to_slug(section)

    augmented = _augment_rows(rows, tech, section_slug, section)

    # Split into automated vs manual
    automated_rows: list[dict] = []
    manual_rows: list[dict] = []

    for row in augmented:
        auto_type = row.get("automation_type", "").strip().lower()
        if auto_type == "manual":
            manual_rows.append(row)
        else:
            automated_rows.append(row)

    # Extract version from the first available row
    first_row = augmented[0] if augmented else {}
    raw_version = first_row.get("framework_version", "v1.0.0")
    version = _extract_version(raw_version, tech)

    display_name = tech_display_name(tech)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    template = env.get_template(_TEMPLATE_FILE)

    return template.render(
        tech=tech,
        category=category,
        section=section,
        section_slug=section_slug,
        tech_display_name=display_name,
        version=version,
        automated_rows=automated_rows,
        manual_rows=manual_rows,
    )


# ─── Output path helper ───────────────────────────────────────────────────────


def check_rule_output_path(
    category: str,
    tech: str,
    section: str,
) -> Path:
    """Return the canonical output path for a check rule YAML.

    Args:
        category: Benchmark category, e.g. ``"database"``.
        tech: Technology key, e.g. ``"postgresql"``.
        section: Raw CIS section string, e.g. ``"6"``.

    Returns:
        Absolute ``Path`` object.
    """
    return (
        _BASE
        / "catalog"
        / "rule"
        / f"{category}_rule_check"
        / tech
        / f"{tech}_cis_section_{section}.rules.yaml"
    )
