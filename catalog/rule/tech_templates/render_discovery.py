#!/usr/bin/env python3
"""
Jinja2-based discovery YAML renderer for CIS Technology compliance rules.

Selects the appropriate template based on the technology transport type and
renders a discovery YAML string suitable for the technology engine.

Usage::

    from catalog.rule.tech_templates.render_discovery import render_discovery

    yaml_str = render_discovery(
        tech="postgresql",
        category="database",
        section="6",
        rows=classified_rows,
    )
"""

import re
import sys
from pathlib import Path
from typing import Union

# ─── Jinja2 import ────────────────────────────────────────────────────────────

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "jinja2 is required for render_discovery.  Install it: pip install jinja2"
    ) from exc

# ─── Utility imports ──────────────────────────────────────────────────────────

_BASE = Path(__file__).resolve().parent.parent.parent.parent  # tech_templates -> rule -> catalog -> repo root
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from catalog.rule.tech_rule_utils import (  # noqa: E402
    make_discovery_id,
    make_slug,
    section_to_slug,
)

# ─── Template directory ───────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent

# ─── Transport map ────────────────────────────────────────────────────────────

TRANSPORT_MAP: dict[str, str] = {
    # linux
    "ubuntu":           "ssh",
    "rhel":             "ssh",
    "debian":           "ssh",
    "suse":             "ssh",
    "centos":           "ssh",
    # database — SQL
    "postgresql":       "sql",
    "mysql":            "sql",
    "oracle_db":        "sql",
    "sql_server":       "sql",
    "mariadb":          "sql",
    "ibm_db2":          "sql",
    # database — NoSQL
    "mongodb":          "mongo",
    "cassandra":        "mongo",
    # container
    "docker":           "docker_api",
    # virtualization
    "vmware_esxi":      "ssh",
    # networking — all SSH/CLI
    "cisco_ios_xe":     "ssh",
    "cisco_asa":        "ssh",
    "cisco_nxos":       "ssh",
    "cisco_ios_xr":     "ssh",
    "cisco_firewall":   "ssh",
    "palo_alto":        "ssh",
    "fortigate":        "ssh",
    "check_point":      "rest_api",
    # web_server
    "apache_http":      "ssh",
    "nginx":            "ssh",
    "tomcat":           "ssh",
    "websphere":        "ssh",
    "iis":              "powershell",
    # cloud_saas / devops
    "microsoft_365":    "rest_api",
    "google_workspace": "rest_api",
    "sharepoint":       "rest_api",
    "dynamics_365":     "rest_api",
    "gitlab":           "rest_api",
    # data
    "snowflake":        "snowflake_sql",
}

# Template filename for each transport type
_TEMPLATE_FILE: dict[str, str] = {
    "ssh":           "discovery_ssh.yaml.j2",
    "sql":           "discovery_sql.yaml.j2",
    "mongo":         "discovery_mongo.yaml.j2",
    "docker_api":    "discovery_docker_api.yaml.j2",
    "rest_api":      "discovery_rest_api.yaml.j2",
    "powershell":    "discovery_powershell.yaml.j2",
    "snowflake_sql": "discovery_snowflake_sql.yaml.j2",
}

# ─── Command / query extraction helpers ───────────────────────────────────────

# Shell keywords and common CLI tools that indicate a command line.
# Deliberately excludes the generic "word + word" pattern to avoid matching
# prose text like "Confirm the..." or "To assess..." as commands.
_SHELL_PATTERN = re.compile(
    r"^\s*"
    r"(?:\$\s+)?"                            # optional leading $
    r"("
    r"grep|awk|sed|cat|cut|find|ls|stat"
    r"|sshd|ssh\b|sysctl|systemctl"
    r"|passwd|chage|id|groups|getent"
    r"|openssl|curl|wget|ps|netstat|ss"
    r"|iptables|firewall-cmd|auditctl"
    r"|mongosh|mongo|nodetool"
    r"|show\b|select\b|set\b"               # SQL/Mongo keywords
    r"|\$\s*\S"                              # any $ command
    r")",
    re.IGNORECASE,
)

_DOLLAR_STRIP = re.compile(r"^\$\s+")

# Matches an inline '$ command' sequence within prose text.
# Used when audit procedures embed commands in a single-line CSV field.
_INLINE_DOLLAR_CMD = re.compile(
    r"\$\s+([a-z][a-z0-9_/.\-]*(?:\s+[^\$\n]{0,120}?)?)"
    r"(?=\s*\$|\s+[A-Z][a-z]|\s*$)",
    re.IGNORECASE,
)


def _extract_first_command(audit_procedure: str) -> str:
    """Return the first shell/CLI command found in *audit_procedure*.

    Scans the string line-by-line for lines that start with ``$``, ``#``, a
    known shell keyword, or a CLI tool name.  Strips a leading ``$ `` prefix
    before returning.

    Args:
        audit_procedure: Raw audit procedure text from the CSV.

    Returns:
        The first command string, or an empty string when none is found.
    """
    if not audit_procedure:
        return ""

    for line in audit_procedure.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Lines starting with $ are shell commands
        if stripped.startswith("$"):
            cmd = _DOLLAR_STRIP.sub("", stripped)
            return cmd.strip()
        # Lines starting with # followed by a keyword (not comments)
        if stripped.startswith("#!") or stripped.startswith("# "):
            continue
        if _SHELL_PATTERN.match(stripped):
            return stripped.strip()

    # No line-start command found — audit procedure may store everything on one
    # line with embedded '$ cmd' sequences (common in database CIS benchmarks).
    m = _INLINE_DOLLAR_CMD.search(audit_procedure)
    if m:
        return m.group(1).strip()

    return ""


_SHOW_PATTERN = re.compile(
    r"SHOW\s+([a-z_][a-z0-9_]*)", re.IGNORECASE
)
_CURRENT_SETTING_PATTERN = re.compile(
    r"current_setting\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE
)

# MySQL-style: SHOW VARIABLES LIKE 'var_name' or SHOW VARIABLES WHERE variable_name = 'var_name'
_SHOW_VARIABLES_LIKE_PATTERN = re.compile(
    r"SHOW\s+(?:GLOBAL\s+|SESSION\s+)?VARIABLES\s+"
    r"(?:LIKE|WHERE\s+variable_name\s*=)\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# MySQL-style: SHOW STATUS LIKE 'var_name'
_SHOW_STATUS_LIKE_PATTERN = re.compile(
    r"SHOW\s+(?:GLOBAL\s+|SESSION\s+)?STATUS\s+LIKE\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# SQL transports that use MySQL syntax (SHOW VARIABLES LIKE) rather than
# PostgreSQL's current_setting().  MariaDB uses the same syntax as MySQL.
_MYSQL_SYNTAX_TRANSPORTS: set[str] = {"mysql", "mariadb", "sql_server", "ibm_db2"}

# Oracle uses SELECT VALUE FROM V$PARAMETER — distinct from both MySQL SHOW and PostgreSQL current_setting
_ORACLE_TRANSPORTS: set[str] = {"oracle_db"}

# Discovery IDs where auto-extraction from the CSV audit procedure produces the wrong SQL.
# Checked in _augment_rows() before any pattern extraction runs — acts as a permanent
# safety net so the correct query survives a future `generate_tech_rules.py --apply` run.
_KNOWN_CORRECT_QUERIES: dict[str, str] = {
    # allow_suspicious_udfs: CIS audit procedure uses the option name as the slug, not the
    # actual variable name — generator would emit SHOW VARIABLES LIKE 'allow_suspicious_udfs_is_set_to_off'
    "mysql.section_4.allow_suspicious_udfs_is_set_to_off": "SHOW VARIABLES LIKE 'allow_suspicious_udfs';",
    # log_raw: same slug-vs-variable-name problem
    "mysql.section_6.log_raw_is_set_to_off": "SHOW VARIABLES LIKE 'log_raw';",
    # secure_mysql_keyring: keyring plugins expose via performance_schema, not SHOW VARIABLES
    "mysql.section_3.secure_mysql_keyring": (
        "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables"
        " WHERE VARIABLE_NAME LIKE 'keyring%';"
    ),
}


def _extract_sql_param(audit_procedure: str) -> str:
    """Return the parameter name from a ``SHOW`` or ``current_setting()`` call.

    Scans *audit_procedure* for:
    - ``SHOW VARIABLES LIKE '<var>'`` (MySQL-style)
    - ``SHOW STATUS LIKE '<var>'`` (MySQL-style)
    - ``current_setting('<var>')`` (PostgreSQL-style)
    - ``SHOW <word>`` (generic fallback)

    Args:
        audit_procedure: Raw audit procedure text from the CSV.

    Returns:
        The parameter name string, or an empty string when none is found.
    """
    if not audit_procedure:
        return ""

    # MySQL SHOW VARIABLES LIKE 'param' — most specific, check first
    m = _SHOW_VARIABLES_LIKE_PATTERN.search(audit_procedure)
    if m:
        return m.group(1)

    # MySQL SHOW STATUS LIKE 'param'
    m = _SHOW_STATUS_LIKE_PATTERN.search(audit_procedure)
    if m:
        return m.group(1)

    # PostgreSQL current_setting('param')
    m = _CURRENT_SETTING_PATTERN.search(audit_procedure)
    if m:
        return m.group(1)

    # Generic SHOW <word> fallback — captures only a single word after SHOW so
    # "SHOW VARIABLES" yields "VARIABLES" (less useful but non-empty)
    m = _SHOW_PATTERN.search(audit_procedure)
    if m:
        return m.group(1)

    return ""


# Known expected values found verbatim in audit_procedure text
_KNOWN_EXPECTED: list[str] = [
    "scram-sha-256",
    "scram_sha_256",
    "on",
    "off",
    "yes",
    "no",
]

_SELECT_STATEMENT_PATTERN = re.compile(
    r"(SELECT\s+.+?;)", re.IGNORECASE | re.DOTALL
)


def _is_os_level_check(audit_procedure: str, tech: str) -> bool:
    """Return True when no extractable SQL exists for *tech* in *audit_procedure*.

    Detects OS-level checks (shell commands only) so the SQL template emits
    ``run_command`` with ``applicable_to: [self_hosted]`` instead of a broken
    placeholder SQL query.

    Args:
        audit_procedure: Raw audit procedure text from the CSV.
        tech: Technology key (e.g. ``"postgresql"``, ``"mysql"``).

    Returns:
        True when the entry should be treated as OS-level (no valid SQL derivable).
    """
    if not audit_procedure or not audit_procedure.strip():
        return True

    # A real SELECT statement is always SQL — not OS-level regardless of tech
    if _SELECT_STATEMENT_PATTERN.search(audit_procedure):
        return False

    if tech in _MYSQL_SYNTAX_TRANSPORTS:
        # Valid SQL only when a specific SHOW VARIABLES / STATUS param is extractable
        m = (_SHOW_VARIABLES_LIKE_PATTERN.search(audit_procedure) or
             _SHOW_STATUS_LIKE_PATTERN.search(audit_procedure))
        if m and m.group(1).lower() not in ("variables", "status", "global", "session"):
            return False
        return True

    if tech in _ORACLE_TRANSPORTS:
        # Valid SQL when any recognisable param can be mapped to V$PARAMETER
        param = _extract_sql_param(audit_procedure)
        if param and param.lower() not in ("variables", "status", "global", "session"):
            return False
        return True

    # PostgreSQL and other SQL transports: valid when current_setting / SHOW param found
    param = _extract_sql_param(audit_procedure)
    if param and param.lower() not in ("variables", "status", "global", "session"):
        return False
    return True


def _extract_select_query(
    audit_procedure: str,
    check_slug: str,
    tech: str = "",
) -> str:
    """Return a SQL query from *audit_procedure*, or a transport-appropriate placeholder.

    Priority:
    1. A SELECT statement found in the text (flattened to one line).
    2. For MySQL-syntax transports: ``SHOW VARIABLES LIKE '<param>'`` derived
       from the audit procedure, or ``SHOW VARIABLES LIKE '<slug>'`` as fallback.
    3. For PostgreSQL-syntax transports: ``SELECT current_setting('<param>')``.

    Args:
        audit_procedure: Raw audit procedure text.
        check_slug: Slug for the check (used in placeholder query).
        tech: Technology key (e.g. ``"mysql"``, ``"postgresql"``).  Used to
            select the correct placeholder syntax.  An empty string defaults
            to PostgreSQL syntax.

    Returns:
        A SQL query string appropriate for the target database.
    """
    use_mysql_syntax  = tech in _MYSQL_SYNTAX_TRANSPORTS
    use_oracle_syntax = tech in _ORACLE_TRANSPORTS

    if audit_procedure:
        m = _SELECT_STATEMENT_PATTERN.search(audit_procedure)
        if m:
            # Flatten to single line
            query = re.sub(r"\s+", " ", m.group(1)).strip()
            return query

        if use_mysql_syntax:
            # Try to extract variable name from SHOW VARIABLES LIKE pattern
            param = _extract_sql_param(audit_procedure)
            if param and param.lower() not in ("variables", "status", "global", "session"):
                return f"SHOW VARIABLES LIKE '{param}';"
            # Fallback: emit a SHOW VARIABLES placeholder for the check slug
            return f"SHOW VARIABLES LIKE '{check_slug}';"
        elif use_oracle_syntax:
            # Oracle: map extracted param name to a V$PARAMETER query
            param = _extract_sql_param(audit_procedure)
            if param and param.lower() not in ("variables", "status", "global", "session"):
                return f"SELECT VALUE FROM V$PARAMETER WHERE NAME = '{param.lower()}';"
            # Fallback placeholder — _is_os_level_check will mark this entry self_hosted
            return f"SELECT VALUE FROM V$PARAMETER WHERE NAME = '{check_slug.lower()}';"
        else:
            # PostgreSQL: convert SHOW <param>; to SELECT current_setting('<param>');
            param = _extract_sql_param(audit_procedure)
            if param:
                return f"SELECT current_setting('{param}');"

    if use_mysql_syntax:
        return f"SHOW VARIABLES LIKE '{check_slug}';"
    if use_oracle_syntax:
        return f"SELECT VALUE FROM V$PARAMETER WHERE NAME = '{check_slug.lower()}';"
    return f"SELECT current_setting('{check_slug}');"


def _extract_snowflake_query(audit_procedure: str, check_slug: str) -> str:
    """Return a Snowflake SQL query from *audit_procedure*, or a placeholder.

    Args:
        audit_procedure: Raw audit procedure text.
        check_slug: Slug for the check (used in placeholder query).

    Returns:
        A Snowflake SQL query string.
    """
    if audit_procedure:
        m = _SELECT_STATEMENT_PATTERN.search(audit_procedure)
        if m:
            query = re.sub(r"\s+", " ", m.group(1)).strip()
            return query

    return f"SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.{check_slug.upper()};"


# ─── Row augmentation ─────────────────────────────────────────────────────────


def _augment_rows(
    rows: list,
    tech: str,
    section_slug: str,
) -> list[dict]:
    """Add computed ``_*`` fields to each row for use in templates.

    Accepts rows that are either plain ``dict`` instances or ``ClassifiedRow``
    named-tuples (in which case the ``.row`` attribute is used).

    Args:
        rows: CSV row dicts or ClassifiedRow items for this (tech, section).
        tech: Technology key.
        section_slug: e.g. ``"section_6"``.

    Returns:
        List of augmented dicts.
    """
    augmented: list[dict] = []
    for r in rows:
        # Support both plain dicts and ClassifiedRow namedtuples
        row: dict = r.row if hasattr(r, "row") else dict(r)

        title = row.get("title", "").strip()
        try:
            check_slug = make_slug(title)
        except ValueError:
            check_slug = "unknown"

        audit_proc = row.get("audit_procedure", "")

        row["_check_slug"] = check_slug
        row["_discovery_id"] = make_discovery_id(tech, section_slug, check_slug)

        # Apply known-correct query override before any pattern extraction so the
        # correct SQL survives future --apply runs regardless of audit procedure text.
        override_query = _KNOWN_CORRECT_QUERIES.get(row["_discovery_id"])
        if override_query is not None:
            row["_ssh_command"] = ""
            row["_param_name"] = ""
            row["_expected_value"] = ""
            row["_sql_query"] = override_query
            row["_snowflake_query"] = ""
            row["_is_os_level"] = False
            row["_applicable_to"] = ["cloud_managed", "self_hosted"]
            augmented.append(row)
            continue

        row["_ssh_command"] = _extract_first_command(audit_proc)
        row["_param_name"] = _extract_sql_param(audit_proc)
        row["_expected_value"] = ""
        row["_sql_query"] = _extract_select_query(audit_proc, check_slug, tech=tech)
        row["_snowflake_query"] = _extract_snowflake_query(audit_proc, check_slug)
        row["_is_os_level"]   = _is_os_level_check(audit_proc, tech)
        row["_applicable_to"] = ["self_hosted"] if row["_is_os_level"] else ["cloud_managed", "self_hosted"]

        augmented.append(row)

    return augmented


# ─── Section description helper ───────────────────────────────────────────────


def _section_description(rows: list[dict], section: str) -> str:
    """Derive a human-readable section description from the first row's title.

    Args:
        rows: Augmented row dicts.
        section: Section number string.

    Returns:
        A short description string.
    """
    if rows:
        # Use the first row's title as the section name hint
        title = rows[0].get("title", "").strip()
        # Strip leading "Ensure/Verify" verb for a cleaner description
        title = re.sub(
            r"^(ensure|verify|check|confirm|make\s+sure)(\s+(that|the))?\s+",
            "",
            title,
            flags=re.IGNORECASE,
        )
        return title.rstrip(".")

    return f"Section {section} controls"


# ─── Public render API ────────────────────────────────────────────────────────


def render_discovery(
    tech: str,
    category: str,
    section: str,
    rows: list,
    section_slug: str = "",
) -> str:
    """Render a discovery YAML string for the given technology and section.

    Selects the Jinja2 template based on the technology's transport type (from
    :data:`TRANSPORT_MAP`), augments each row with computed ``_*`` fields, and
    renders the template.

    Args:
        tech: Technology key, e.g. ``"postgresql"``.
        category: Benchmark category, e.g. ``"database"``.
        section: Raw CIS section string, e.g. ``"6"`` or ``"1.2"``.
        rows: CSV row dicts or ClassifiedRow items for this (tech, section).
            Only ``automated_config`` rows should be passed.
        section_slug: Pre-computed section slug.  Derived from *section* when
            empty (the default).

    Returns:
        Rendered YAML string.

    Raises:
        NotImplementedError: When *tech* is not in :data:`TRANSPORT_MAP`.
    """
    if tech not in TRANSPORT_MAP:
        raise NotImplementedError(
            f"No transport defined for tech {tech!r}.  "
            f"Add it to TRANSPORT_MAP in render_discovery.py."
        )

    transport = TRANSPORT_MAP[tech]
    template_file = _TEMPLATE_FILE[transport]

    if not section_slug:
        section_slug = section_to_slug(section)

    augmented = _augment_rows(rows, tech, section_slug)
    description = _section_description(augmented, section)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    template = env.get_template(template_file)

    return template.render(
        tech=tech,
        category=category,
        section=section,
        section_slug=section_slug,
        transport=transport,
        rows=augmented,
        description=description,
    )


# ─── Output path helper ───────────────────────────────────────────────────────


def discovery_output_path(
    category: str,
    tech: str,
    section: str,
) -> Path:
    """Return the canonical output path for a discovery YAML.

    Args:
        category: Benchmark category, e.g. ``"database"``.
        tech: Technology key, e.g. ``"postgresql"``.
        section: Raw CIS section string, e.g. ``"6"``.

    Returns:
        Absolute ``Path`` object.
    """
    sec_slug = section_to_slug(section)
    return (
        _BASE
        / "catalog"
        / "discovery_generator_data"
        / category
        / tech
        / f"step6_{sec_slug}.discovery.yaml"
    )
