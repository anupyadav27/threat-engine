#!/usr/bin/env python3
"""
Slug generation and rule-ID normalization utilities for the CIS Technology
compliance rule generator.

All generators in the tech sprint (TEC-001 through TEC-005) import from this
module to ensure consistent, collision-free slug and rule-ID production.

Usage:
    from catalog.rule.tech_rule_utils import (
        make_slug,
        make_rule_id,
        make_discovery_id,
        section_to_slug,
        tech_display_name,
        SlugRegistry,
    )
"""

import re
import sys
from pathlib import Path


# ─── Leading-verb stripping ────────────────────────────────────────────────────

# Verbs that are stripped only when they appear as the very first word,
# optionally followed by "that" or "the" (up to one article/connector).
_STRIP_VERBS = re.compile(
    r"^(ensure|verify|check|confirm|make\s+sure)"
    r"(\s+(that|the))?\s+",
    re.IGNORECASE,
)

# ─── Known tech display-name overrides ────────────────────────────────────────

_DISPLAY_NAMES: dict[str, str] = {
    "postgresql":        "PostgreSQL",
    "mysql":             "MySQL",
    "ibm_db2":           "IBM DB2",
    "mongodb":           "MongoDB",
    "cassandra":         "Cassandra",
    "cisco_ios_xe":      "Cisco IOS XE",
    "cisco_ios_xr":      "Cisco IOS XR",
    "cisco_nxos":        "Cisco NX-OS",
    "cisco_asa":         "Cisco ASA",
    "cisco_firewall":    "Cisco Firewall",
    "palo_alto":         "Palo Alto Networks",
    "fortigate":         "Fortinet FortiGate",
    "check_point":       "Check Point",
    "vmware_esxi":       "VMware ESXi",
    "apache_http":       "Apache HTTP Server",
    "iis":               "Microsoft IIS",
    "tomcat":            "Apache Tomcat",
    "websphere":         "IBM WebSphere",
    "microsoft_365":     "Microsoft 365",
    "google_workspace":  "Google Workspace",
    "sharepoint":        "Microsoft SharePoint",
    "dynamics_365":      "Microsoft Dynamics 365",
    "gitlab":            "GitLab",
    "snowflake":         "Snowflake",
    "nginx":             "NGINX",
    "docker":            "Docker",
    "ubuntu":            "Ubuntu",
    "rhel":              "Red Hat Enterprise Linux",
    "centos":            "CentOS",
    "debian":            "Debian",
    "suse":              "SUSE Linux",
    "mariadb":           "MariaDB",
    "sql_server":        "Microsoft SQL Server",
}


# ─── Public API ────────────────────────────────────────────────────────────────


def make_slug(title: str) -> str:
    """Produce a snake_case slug from a CIS control title.

    Rules applied in order:
    1. Lowercase the entire string.
    2. Strip leading verbs: "ensure", "verify", "check", "confirm", "make
       sure", optionally followed by "that" or "the".
    3. Replace all non-alphanumeric characters with underscores.
    4. Collapse consecutive underscores to a single underscore.
    5. Strip leading and trailing underscores.
    6. Truncate to 50 characters at a word boundary (last underscore ≤ 50).
    7. Result must match [a-z0-9_]+; raise ValueError if empty.

    Args:
        title: A raw CIS control title string.

    Returns:
        A lowercase snake_case slug.

    Raises:
        ValueError: When the title reduces to an empty string after all
            transforms.

    Examples:
        >>> make_slug("Ensure SSL is enabled for all connections")
        'ssl_is_enabled_for_all_connections'
        >>> make_slug("Verify that audit logging is enabled")
        'audit_logging_is_enabled'
    """
    # Step 1: lowercase
    s = title.lower()

    # Step 2: strip leading verb (only as very first word(s))
    s = _STRIP_VERBS.sub("", s)

    # Step 3: replace non-alphanumeric chars with underscores
    s = re.sub(r"[^a-z0-9]+", "_", s)

    # Step 4: collapse consecutive underscores
    s = re.sub(r"_+", "_", s)

    # Step 5: strip leading/trailing underscores
    s = s.strip("_")

    # Step 6: truncate at 50 chars on a word boundary
    if len(s) > 50:
        truncated = s[:50]
        last_under = truncated.rfind("_")
        if last_under > 0:
            s = truncated[:last_under]
        else:
            s = truncated

    # Step 7: validate
    if not s:
        raise ValueError(f"slug is empty for title: {title!r}")
    if not re.fullmatch(r"[a-z0-9_]+", s):
        raise ValueError(
            f"slug {s!r} does not match [a-z0-9_]+ for title: {title!r}"
        )

    return s


def make_rule_id(tech: str, section: str, slug: str) -> str:
    """Assemble a canonical check rule ID.

    Format: ``{tech}.cis.{section_normalised}.{slug}``

    ``section_normalised`` replaces dots with underscores so that hierarchical
    section numbers like "1.2" become "1_2" (dots are reserved as separators
    between the four top-level components).

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        section: Raw CIS section string, e.g. ``"6"`` or ``"1.2"``.
        slug: Already-generated slug for this rule.

    Returns:
        A dot-separated rule ID string.

    Examples:
        >>> make_rule_id("postgresql", "6", "ssl_is_enabled")
        'postgresql.cis.6.ssl_is_enabled'
        >>> make_rule_id("ubuntu", "1.2", "audit_logging_enabled")
        'ubuntu.cis.1_2.audit_logging_enabled'
    """
    section_norm = section.replace(".", "_")
    return f"{tech}.cis.{section_norm}.{slug}"


def make_ciem_rule_id(tech: str, slug: str) -> str:
    """Assemble a canonical CIEM rule ID.

    Format: ``tciem.{tech}.{slug}``

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        slug: Already-generated slug for this rule.

    Returns:
        A dot-separated CIEM rule ID string.

    Examples:
        >>> make_ciem_rule_id("postgresql", "login_failure_threshold")
        'tciem.postgresql.login_failure_threshold'
    """
    return f"tciem.{tech}.{slug}"


def make_discovery_id(tech: str, section_slug: str, check_slug: str) -> str:
    """Assemble a discovery scope ID.

    Format: ``{tech}.{section_slug}.{check_slug}``

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        section_slug: Section converted to slug via :func:`section_to_slug`,
            e.g. ``"section_6"``.
        check_slug: Slug for this particular check.

    Returns:
        A dot-separated discovery ID string.

    Examples:
        >>> make_discovery_id("postgresql", "section_6", "ssl_is_enabled")
        'postgresql.section_6.ssl_is_enabled'
    """
    return f"{tech}.{section_slug}.{check_slug}"


def section_to_slug(section: str) -> str:
    """Convert a CIS section number to a directory-safe slug.

    Rules:
    - Replace dots with underscores.
    - Prepend ``"section_"``.

    Args:
        section: Raw CIS section string, e.g. ``"1"``, ``"1.2"``, ``"10"``.

    Returns:
        A slug string prefixed with ``"section_"``.

    Examples:
        >>> section_to_slug("1")
        'section_1'
        >>> section_to_slug("1.2")
        'section_1_2'
        >>> section_to_slug("10")
        'section_10'
    """
    normalized = section.replace(".", "_")
    return f"section_{normalized}"


def tech_display_name(tech: str) -> str:
    """Return a human-readable display name for a benchmark_subcategory value.

    Used in YAML ``cis_benchmark`` headers and file descriptions.

    For known technologies a curated override is returned exactly as specified.
    For unknown values the default is title-case after replacing underscores
    with spaces (e.g. ``"oracle_db"`` → ``"Oracle Db"``).

    Args:
        tech: A ``benchmark_subcategory`` string such as ``"postgresql"``.

    Returns:
        A display-name string.

    Examples:
        >>> tech_display_name("postgresql")
        'PostgreSQL'
        >>> tech_display_name("oracle_db")
        'Oracle Db'
    """
    if tech in _DISPLAY_NAMES:
        return _DISPLAY_NAMES[tech]
    return tech.replace("_", " ").title()


# ─── Slug registry (per-scope uniqueness) ─────────────────────────────────────


class SlugRegistry:
    """Track used slugs within a ``(tech, section)`` scope for uniqueness.

    When two different titles produce the same base slug, a numeric suffix
    (``_2``, ``_3``, …) is appended to the later occurrence.

    This class is **not** thread-safe.  Instantiate one per ``(tech, section)``
    grouping and use it for all rows in that group.

    Examples:
        >>> reg = SlugRegistry()
        >>> reg.register("ssl_enabled")
        'ssl_enabled'
        >>> reg.register("ssl_enabled")
        'ssl_enabled_2'
        >>> reg.register("ssl_enabled")
        'ssl_enabled_3'
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def register(self, base_slug: str) -> str:
        """Return a unique slug derived from *base_slug*.

        Returns *base_slug* unchanged on first use; appends ``_2``, ``_3``, …
        on subsequent collisions.  Recursive to handle edge cases where a
        suffixed candidate was itself already registered.

        Args:
            base_slug: The desired slug (output of :func:`make_slug`).

        Returns:
            A unique slug string within this registry's scope.
        """
        if base_slug not in self._seen:
            self._seen[base_slug] = 1
            return base_slug
        self._seen[base_slug] += 1
        candidate = f"{base_slug}_{self._seen[base_slug]}"
        # Recurse in case the candidate itself has already been registered
        return self.register(candidate)

    def reset(self) -> None:
        """Clear all registrations so the same slug can be re-registered."""
        self._seen.clear()


# ─── __main__ collision uniqueness test ───────────────────────────────────────


def _run_collision_test(csv_path: Path) -> None:
    """Load the full CSV and assert uniqueness / low collision rate.

    Rows are deduplicated by ``(benchmark_subcategory, section, title)`` first
    (keeping the highest ``framework_version``) to remove cross-version
    duplicates that would otherwise inflate the collision count.

    Groups by ``(benchmark_category, benchmark_subcategory, section)``,
    instantiates a :class:`SlugRegistry` per group, and calls
    ``registry.register(make_slug(title))`` for each row.

    Asserts:
    - Total collision rate < 5% of deduplicated automated rows.
    - Zero duplicate ``rule_id`` values within any ``(tech, section)`` group.

    Args:
        csv_path: Absolute path to ``cis_technology_compliance_rules.csv``.
    """
    import csv
    from collections import defaultdict

    print(f"Loading CSV: {csv_path}")

    # Dedup by (tech, section, title) — keep highest framework_version
    best: dict[tuple[str, str, str], dict] = {}
    raw_total = 0
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            raw_total += 1
            tech = row.get("benchmark_subcategory", "").strip()
            section = row.get("section", "").strip()
            title = row.get("title", "").strip()
            key = (tech, section, title)
            if key not in best:
                best[key] = row
            else:
                if row.get("framework_version", "") > best[key].get("framework_version", ""):
                    best[key] = row

    rows: list[dict] = list(best.values())
    print(f"Total rows (raw): {raw_total}")
    print(f"Total rows (deduped by tech/section/title): {len(rows)}")

    # Group rows by (category, tech, section)
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    skipped = 0
    for row in rows:
        cat = row.get("benchmark_category", "").strip()
        tech = row.get("benchmark_subcategory", "").strip()
        section = row.get("section", "").strip()
        if not tech or not section:
            skipped += 1
            continue
        groups[(cat, tech, section)].append(row)

    print(f"Groups: {len(groups)}  |  Skipped (missing field): {skipped}")

    total_automated = 0
    total_collisions = 0
    duplicate_rule_ids = 0

    for (cat, tech, section), group_rows in groups.items():
        registry = SlugRegistry()
        seen_rule_ids: set[str] = set()

        for row in group_rows:
            auto_type = row.get("automation_type", "").strip().lower()
            if auto_type != "automated":
                continue

            total_automated += 1
            title = row.get("title", "").strip()
            try:
                base = make_slug(title)
            except ValueError:
                continue

            final = registry.register(base)
            if final != base:
                total_collisions += 1

            rule_id = make_rule_id(tech, section, final)
            if rule_id in seen_rule_ids:
                duplicate_rule_ids += 1
                print(
                    f"  [DUPLICATE] rule_id={rule_id!r} in ({cat}, {tech}, {section})"
                )
            seen_rule_ids.add(rule_id)

    collision_rate = total_collisions / total_automated if total_automated else 0.0
    print(f"\nResults:")
    print(f"  Automated rows     : {total_automated}")
    print(f"  Collisions handled : {total_collisions}")
    print(f"  Collision rate     : {collision_rate:.2%}")
    print(f"  Duplicate rule_ids : {duplicate_rule_ids}")

    assert collision_rate < 0.05, (
        f"Collision rate {collision_rate:.2%} exceeds 5% threshold "
        f"({total_collisions}/{total_automated})"
    )
    assert duplicate_rule_ids == 0, (
        f"{duplicate_rule_ids} duplicate rule_id(s) found within (tech, section) groups"
    )

    print("\nAll assertions passed.")


if __name__ == "__main__":
    _DEFAULT_CSV = (
        Path(__file__).resolve().parent.parent
        / "complaince_csv"
        / "cis_technology_compliance_rules.csv"
    )
    csv_file = Path(sys.argv[1]) if len(sys.argv) > 1 else _DEFAULT_CSV
    if not csv_file.exists():
        print(f"CSV not found: {csv_file}", file=sys.stderr)
        sys.exit(1)
    _run_collision_test(csv_file)
