#!/usr/bin/env python3
"""
Jinja2-based CIEM detection-rule YAML renderer for CIS Technology compliance rules.

Renders a CIEM rule YAML string for a given tech, aggregating all CIEM-classified
rows across all sections into a single file.

Usage::

    from catalog.rule.tech_templates.render_ciem import render_ciem_rules, classify_ciem_row

    yaml_str = render_ciem_rules(
        tech="postgresql",
        category="database",
        rows=ciem_classified_rows,
    )
"""

import sys
import warnings
from pathlib import Path
from typing import Optional

# ─── Jinja2 import ────────────────────────────────────────────────────────────

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "jinja2 is required for render_ciem.  Install it: pip install jinja2"
    ) from exc

# ─── Utility imports ──────────────────────────────────────────────────────────

_BASE = Path("/Users/apple/Desktop/threat-engine")
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from catalog.rule.tech_rule_utils import make_slug, make_ciem_rule_id  # noqa: E402

# ─── Template directory ───────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent
_TEMPLATE_FILE = "ciem_rule.yaml.j2"

# ─── Log source map (all 34 supported techs) ─────────────────────────────────

LOG_SOURCE_MAP: dict[str, str] = {
    "ubuntu":           "/var/log/auth.log, auditd",
    "rhel":             "/var/log/secure, auditd",
    "debian":           "/var/log/auth.log, auditd",
    "suse":             "/var/log/messages, auditd",
    "centos":           "/var/log/secure, auditd",
    "postgresql":       "pg_log, pg_audit",
    "mysql":            "general_log, error_log",
    "mariadb":          "general_log, error_log",
    "oracle_db":        "audit_trail, v$xml_audit_trail",
    "sql_server":       "SQL Server Audit, Error Log",
    "ibm_db2":          "db2audit, db2diag",
    "mongodb":          "mongod.log",
    "cassandra":        "system.log, audit.log",
    "docker":           "dockerd journal, /var/log/docker.log",
    "vmware_esxi":      "syslog, /var/log/vmkernel.log",
    "cisco_ios_xe":     "syslog, SNMP trap",
    "cisco_asa":        "syslog",
    "cisco_nxos":       "syslog, SNMP trap",
    "cisco_ios_xr":     "syslog, SNMP trap",
    "cisco_firewall":   "syslog",
    "palo_alto":        "syslog, Panorama",
    "fortigate":        "FortiAnalyzer, syslog",
    "check_point":      "SmartLog, syslog",
    "apache_http":      "/var/log/httpd/access_log, error_log",
    "nginx":            "/var/log/nginx/access.log, error.log",
    "iis":              "IIS logs, Windows Event Log",
    "tomcat":           "catalina.out, access_log",
    "websphere":        "SystemOut.log, audit.log",
    "microsoft_365":    "Microsoft 365 Unified Audit Log",
    "google_workspace": "Google Workspace Admin Audit",
    "sharepoint":       "SharePoint Unified Audit Log",
    "dynamics_365":     "Microsoft 365 Unified Audit Log",
    "snowflake":        "SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY",
    "gitlab":           "GitLab Audit Events API",
}

# ─── CIEM keyword → event_type / MITRE mapping ───────────────────────────────

# Each tuple: (keywords, event_type, mitre_technique, mitre_tactic)
# Ordered from most specific to least specific.
CIEM_KEYWORD_TO_EVENT: list[tuple[list[str], str, str, str]] = [
    # Brute force / authentication failures — check before generic "login"
    (
        [
            "brute",
            "login fail",
            "logon fail",
            "authentication fail",
            "failed login",
            "failed logon",
            "invalid password",
            "repeated fail",
        ],
        "authentication_failure",
        "T1110",
        "credential_access",
    ),
    # Successful / interactive login
    (
        [
            "login",
            "logon",
            "sign-in",
            "successful login",
            "successful logon",
            "user login",
            "user access",
            "interactive login",
        ],
        "authentication_success",
        "T1078",
        "initial_access",
    ),
    # Privilege escalation
    (
        [
            "privilege",
            "sudo",
            "escalat",
            "admin grant",
            "role grant",
            "elevation",
            "root access",
            "superuser",
            "dba",
            "become",
        ],
        "privilege_change",
        "T1068",
        "privilege_escalation",
    ),
    # Off-hours / anomalous time access
    (
        [
            "off-hours",
            "off hours",
            "outside business",
            "outside working",
            "non-business",
            "unusual time",
            "after hours",
        ],
        "authentication_success",
        "T1078",
        "initial_access",
    ),
    # Configuration / policy changes
    (
        [
            "config change",
            "configuration change",
            "policy change",
            "setting change",
            "modified",
            "audit disable",
            "logging disable",
            "firewall change",
        ],
        "configuration_change",
        "T1562",
        "defense_evasion",
    ),
    # Data export / exfiltration
    (
        [
            "data access",
            "data export",
            "data download",
            "bulk download",
            "sensitive data",
            "exfiltrat",
            "query large",
        ],
        "data_access",
        "T1530",
        "collection",
    ),
    # Audit / monitoring events
    (
        [
            "audit",
            "audit log",
            "audit trail",
            "monitoring",
            "logging",
        ],
        "audit_event",
        "T1562",
        "defense_evasion",
    ),
    # Generic access catch-all
    (
        ["access"],
        "resource_access",
        "T1078",
        "initial_access",
    ),
    # Generic change catch-all
    (
        ["change"],
        "configuration_change",
        "T1562",
        "defense_evasion",
    ),
]


# ─── Classification helper (public — imported by TEC-001) ────────────────────


def classify_ciem_row(row: dict) -> Optional[tuple[str, str, str]]:
    """Determine whether a CSV row is a CIEM rule and return detection metadata.

    Scans the combined title + description text for CIEM-relevant keywords in
    priority order.  The first matching entry wins.

    Args:
        row: A CSV row dict with at minimum ``"title"`` and ``"description"``
            keys.

    Returns:
        A ``(event_type, mitre_technique, mitre_tactic)`` tuple when a CIEM
        keyword is found, or ``None`` when no keyword matches.

    Examples:
        >>> classify_ciem_row({"title": "Ensure brute force protection", "description": ""})
        ('authentication_failure', 'T1110', 'credential_access')
        >>> classify_ciem_row({"title": "Ensure SSL is enabled", "description": "TLS config"})
        None
    """
    text = (row.get("title", "") + " " + row.get("description", "")).lower()
    for keywords, event_type, technique, tactic in CIEM_KEYWORD_TO_EVENT:
        if any(kw in text for kw in keywords):
            return event_type, technique, tactic
    return None


# ─── Row augmentation ─────────────────────────────────────────────────────────


def _augment_rows(rows: list[dict], tech: str) -> list[dict]:
    """Add ``_ciem_slug``, ``_event_type``, ``_mitre_technique``, and
    ``_mitre_tactic`` to each row.

    Rows that do not match any CIEM keyword are still included — they fall back
    to ``resource_access`` / ``T1078`` / ``initial_access``.

    Args:
        rows: List of CSV row dicts classified as CIEM.
        tech: Technology key used for slug collision-free generation within
            this call.  A per-call registry handles duplicates.

    Returns:
        List of augmented dicts ready for template rendering.
    """
    seen_slugs: dict[str, int] = {}
    augmented: list[dict] = []

    for r in rows:
        row: dict = r.row if hasattr(r, "row") else dict(r)

        title = row.get("title", "").strip()
        try:
            base_slug = make_slug(title)
        except ValueError:
            base_slug = "unknown"

        # Uniqueness within this tech's CIEM file
        if base_slug not in seen_slugs:
            seen_slugs[base_slug] = 1
            slug = base_slug
        else:
            seen_slugs[base_slug] += 1
            slug = f"{base_slug}_{seen_slugs[base_slug]}"

        classification = classify_ciem_row(row)
        if classification is not None:
            event_type, technique, tactic = classification
        else:
            # Fallback for rows already pre-classified as CIEM by the caller
            event_type, technique, tactic = "resource_access", "T1078", "initial_access"

        row["_ciem_slug"] = slug
        row["_event_type"] = event_type
        row["_mitre_technique"] = technique
        row["_mitre_tactic"] = tactic

        # Ensure remediation_steps key is always present
        if "remediation_steps" not in row:
            row["remediation_steps"] = row.get("remediation", "")

        augmented.append(row)

    return augmented


# ─── Public render API ────────────────────────────────────────────────────────


def render_ciem_rules(
    tech: str,
    category: str,
    rows: list[dict],
) -> str:
    """Render the ciem_rule.yaml.j2 template for one technology.

    All CIEM-classified rows for this tech (across all CIS sections) are
    combined into a single ``rules:`` list.

    Args:
        tech: Technology key, e.g. ``"ubuntu"``, ``"postgresql"``.
        category: Benchmark category, e.g. ``"linux"``, ``"database"``.
        rows: CIEM-classified CSV row dicts for this tech.  Each row must
            contain at minimum: ``"title"``, ``"control_id"``, ``"section"``,
            ``"severity"``.

    Returns:
        Rendered YAML string with top-level keys ``tech_type``, ``category``,
        ``log_source``, and ``rules``.
    """
    # Resolve log source — warn if missing
    if tech in LOG_SOURCE_MAP:
        log_source = LOG_SOURCE_MAP[tech]
    else:
        warnings.warn(
            f"[WARN] LOG_SOURCE_MAP missing entry for {tech!r}, defaulting to syslog",
            stacklevel=2,
        )
        log_source = "syslog"

    augmented = _augment_rows(rows, tech)

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
        log_source=log_source,
        rows=augmented,
    )


# ─── Output path helper ───────────────────────────────────────────────────────


def ciem_rule_output_path(category: str, tech: str) -> Path:
    """Return the canonical output path for a CIEM rule YAML.

    One file per tech (all sections combined).

    Args:
        category: Benchmark category, e.g. ``"linux"``.
        tech: Technology key, e.g. ``"ubuntu"``.

    Returns:
        Absolute ``Path`` object.
    """
    return (
        _BASE
        / "catalog"
        / "rule"
        / f"{category}_rule_ciem"
        / tech
        / f"{tech}_ciem_rules.yaml"
    )
