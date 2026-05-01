#!/usr/bin/env python3
"""
Jinja2-based metadata YAML renderer for CIS Technology compliance rules.

Renders a metadata YAML string for a given tech, combining ALL rows (both
automated and manual) from all CIS sections into a single aggregated file.

Usage::

    from catalog.rule.tech_templates.render_metadata import render_metadata

    yaml_str = render_metadata(
        tech="postgresql",
        category="database",
        rows=all_rows_for_this_tech,
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
        "jinja2 is required for render_metadata.  Install it: pip install jinja2"
    ) from exc

# ─── Utility imports ──────────────────────────────────────────────────────────

_BASE = Path("/Users/apple/Desktop/threat-engine")
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from catalog.rule.tech_rule_utils import (  # noqa: E402
    make_rule_id,
    make_slug,
    tech_display_name,
)

# ─── Template directory ───────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent
_TEMPLATE_FILE = "metadata.yaml.j2"

# ─── Text sanitisation ───────────────────────────────────────────────────────

# Collapse runs of 3+ blank lines to a single blank line
_MULTI_BLANK = re.compile(r"\n{3,}")


def _sanitise(text: str) -> str:
    """Sanitise a multi-line text field for YAML rendering.

    Steps applied:
    1. Strip leading/trailing whitespace.
    2. Collapse runs of 3+ blank lines to a single blank line.
    3. Replace double-quote characters with single-quotes.

    Args:
        text: Raw field value from the CSV row.

    Returns:
        Sanitised string, guaranteed non-None.  Empty input returns ``""``.
    """
    if not text:
        return ""
    s = text.strip()
    s = _MULTI_BLANK.sub("\n\n", s)
    s = s.replace('"', "'")
    return s


# ─── References list parser ───────────────────────────────────────────────────

# Match numbered or bulleted list prefixes: "1.", "1)", "•", "·", "-", "*"
_LIST_PREFIX = re.compile(r"^\s*(?:\d+[.)]\s*|[•·\-\*]\s*)")


def _parse_references(references_raw: str) -> list[str]:
    """Parse a raw ``references`` CSV field into a list of individual refs.

    Splits on:
    - Newlines
    - Semicolons
    - Numbered prefixes (``1.``, ``1)``)

    Strips list-item prefixes and blank entries.

    Args:
        references_raw: Raw references field from the CSV.

    Returns:
        List of reference strings.  Returns ``[]`` when input is empty.
    """
    if not references_raw or not references_raw.strip():
        return []

    # Split on newlines and semicolons
    parts: list[str] = re.split(r"[\n;]+", references_raw)
    result: list[str] = []
    for part in parts:
        # Further split on numbered prefixes if a part contains multiple items
        sub_parts = re.split(r"(?=\b\d+[.)]\s)", part)
        for sp in sub_parts:
            clean = _LIST_PREFIX.sub("", sp).strip()
            if clean:
                result.append(clean)
    return result


# ─── Deduplication ────────────────────────────────────────────────────────────


def _deduplicate_rows(rows: list[dict]) -> list[dict]:
    """Keep only the highest ``framework_version`` row per ``unique_compliance_id``.

    Rows without a ``unique_compliance_id`` are always included unchanged.
    Lexicographic comparison is used for version strings (sufficient for the
    version formats present in this CSV).

    Args:
        rows: All rows for a single tech (all sections, automated + manual).

    Returns:
        Deduplicated list of rows.
    """
    best: dict[str, dict] = {}
    no_id: list[dict] = []

    for r in rows:
        # Support both plain dicts and ClassifiedRow namedtuples
        row: dict = r.row if hasattr(r, "row") else dict(r)
        uid = row.get("unique_compliance_id", "").strip()
        if not uid:
            no_id.append(row)
            continue
        if uid not in best:
            best[uid] = row
        else:
            current_version = row.get("framework_version", "")
            existing_version = best[uid].get("framework_version", "")
            if current_version > existing_version:
                best[uid] = row

    return list(best.values()) + no_id


# ─── Row augmentation ─────────────────────────────────────────────────────────


def _augment_rows(rows: list[dict], tech: str) -> list[dict]:
    """Add ``_rule_id`` and sanitised text fields to each row.

    Args:
        rows: Deduplicated CSV row dicts for this tech.
        tech: Technology key (used for rule ID construction).

    Returns:
        List of augmented dicts ready for template rendering.
    """
    augmented: list[dict] = []
    seen_slugs: dict[str, int] = {}

    for r in rows:
        row: dict = r.row if hasattr(r, "row") else dict(r)

        title = row.get("title", "").strip()
        section = row.get("section", "").strip()

        try:
            base_slug = make_slug(title)
        except ValueError:
            base_slug = "unknown"

        # Uniqueness within this tech's metadata file (global, not per-section)
        slug_key = f"{section}:{base_slug}"
        if slug_key not in seen_slugs:
            seen_slugs[slug_key] = 1
            slug = base_slug
        else:
            seen_slugs[slug_key] += 1
            slug = f"{base_slug}_{seen_slugs[slug_key]}"

        row["_rule_id"] = make_rule_id(tech, section, slug)

        # Sanitised text fields
        row["_description"] = _sanitise(row.get("description", ""))
        row["_rationale"] = _sanitise(row.get("rationale", ""))
        row["_audit_procedure"] = _sanitise(row.get("audit_procedure", ""))
        row["_remediation_steps"] = _sanitise(row.get("remediation_steps", ""))
        row["_references"] = _sanitise(row.get("references", ""))
        row["_impact"] = _sanitise(row.get("impact", ""))

        # Ensure required fields have defaults for empty CSV cells
        for field in (
            "benchmark_category",
            "benchmark_subcategory",
            "automation_type",
            "framework",
            "framework_version",
            "control_id",
            "section",
            "profile_applicability",
            "unique_compliance_id",
        ):
            if not row.get(field):
                row[field] = ""

        augmented.append(row)

    return augmented


# ─── Public render API ────────────────────────────────────────────────────────


def render_metadata(
    tech: str,
    category: str,
    rows: list[dict],
) -> str:
    """Render the metadata.yaml.j2 template for one technology.

    All rows (automated + manual) for this tech across all CIS sections are
    combined.  Duplicate ``unique_compliance_id`` entries keep only the row
    with the highest ``framework_version``.

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        category: Benchmark category, e.g. ``"database"``.
        rows: ALL CSV row dicts for this tech (all sections, all
            automation_types).

    Returns:
        Rendered YAML string with top-level keys ``tech_type``, ``category``,
        ``cis_benchmark``, ``generated_by``, and ``rules``.
    """
    deduped = _deduplicate_rows(rows)
    augmented = _augment_rows(deduped, tech)

    display = tech_display_name(tech)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=False,
        lstrip_blocks=False,
    )
    template = env.get_template(_TEMPLATE_FILE)

    return template.render(
        tech=tech,
        category=category,
        tech_display=display,
        rows=augmented,
    )


# ─── Output path helper ───────────────────────────────────────────────────────


def metadata_output_path(category: str, tech: str) -> Path:
    """Return the canonical output path for a tech metadata YAML.

    One file per tech (all sections combined).

    Args:
        category: Benchmark category, e.g. ``"database"``.
        tech: Technology key, e.g. ``"postgresql"``.

    Returns:
        Absolute ``Path`` object.
    """
    return (
        _BASE
        / "catalog"
        / "rule"
        / f"{category}_rule_metadata"
        / tech
        / f"{tech}_metadata.yaml"
    )
