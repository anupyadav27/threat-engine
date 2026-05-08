#!/usr/bin/env python3
"""
generate_tech_catalog.py
========================
Generates stub YAML files for the Technology Engine catalog:
  catalog/discovery_generator_data/{category}/{technology}/step6_*.discovery.yaml
  catalog/rule/{category}_rule_check/{technology}/{rule_id}.yaml
  catalog/rule/{category}_rule_ciem/{technology}/{rule_id}.yaml

Run:
    python catalog/generate_tech_catalog.py           # dry-run (print only)
    python catalog/generate_tech_catalog.py --apply   # write files

One stub per action type per technology. Real rules to be filled in per sprint.
"""
from __future__ import annotations

import argparse
import os
import textwrap
from pathlib import Path
from typing import Dict, List, Tuple

CATALOG_ROOT = Path(__file__).parent
DISC_ROOT    = CATALOG_ROOT / "discovery_generator_data"
RULE_ROOT    = CATALOG_ROOT / "rule"

# ── Technology registry ────────────────────────────────────────────────────────
# Format: (category, tech_id, display_name, action_type, cis_benchmark, cis_section, log_source)

TECHNOLOGIES: List[Tuple] = [
    # --- DATABASE ---
    ("db", "postgres",  "PostgreSQL",        "query_setting",  "CIS PostgreSQL 15",          "3",  "pgaudit / pg_log"),
    ("db", "mysql",     "MySQL",             "query_table",    "CIS MySQL 8.0",              "3",  "audit_log plugin"),
    ("db", "mariadb",   "MariaDB",           "query_table",    "CIS MariaDB 10.6",           "3",  "MariaDB Audit Plugin"),
    ("db", "mssql",     "SQL Server",        "query_table",    "CIS SQL Server 2019",        "3",  "SQL Server Audit"),
    ("db", "mongodb",   "MongoDB",           "command",        "CIS MongoDB 6.0",            "3",  "mongod audit log (JSON)"),
    ("db", "oracle",    "Oracle Database",   "query_table",    "CIS Oracle Database 19c",    "4",  "Unified Auditing"),
    ("db", "cassandra", "Apache Cassandra",  "cql_query",      "CIS Apache Cassandra 4.0",   "3",  "system_auth / audit log"),
    ("db", "ibm_db2",   "IBM Db2",           "query_table",    "CIS IBM Db2 11.5",           "3",  "DB2 Audit Facility"),

    # --- LINUX ---
    ("linux", "ubuntu",        "Ubuntu Server",       "ssh_command", "CIS Ubuntu 22.04 LTS",     "1", "/var/log/auth.log, auditd"),
    ("linux", "debian",        "Debian Linux",        "ssh_command", "CIS Debian Linux 11",       "1", "/var/log/auth.log, auditd"),
    ("linux", "centos",        "CentOS",              "ssh_command", "CIS CentOS Linux 7",        "1", "/var/log/secure, auditd"),
    ("linux", "redhat",        "Red Hat Enterprise",  "ssh_command", "CIS RHEL 9",                "1", "/var/log/secure, auditd"),
    ("linux", "suse",          "SUSE Linux Enterprise","ssh_command","CIS SUSE 15",               "1", "/var/log/messages, auditd"),
    ("linux", "alibaba_linux", "Alibaba Cloud Linux", "ssh_command", "CIS Alibaba Cloud Linux 3", "1", "/var/log/secure, auditd"),

    # --- NETWORK ---
    ("network", "cisco_ios",   "Cisco IOS",              "cli_command",  "CIS Cisco IOS 15",        "1", "syslog / NetFlow"),
    ("network", "cisco_iosxe", "Cisco IOS XE",           "cli_command",  "CIS Cisco IOS XE 17",     "1", "syslog / RESTCONF"),
    ("network", "cisco_asa",   "Cisco ASA Firewall",     "cli_command",  "CIS Cisco ASA 9.x",       "1", "syslog ASDM"),
    ("network", "cisco_nxos",  "Cisco NX-OS",            "cli_command",  "CIS Cisco NX-OS 9.3",     "1", "syslog / NX-API"),
    ("network", "palo_alto",   "Palo Alto PAN-OS",       "api_call",     "CIS Palo Alto PAN-OS 10", "1", "PAN-OS syslog / Panorama"),
    ("network", "fortinet",    "Fortinet FortiGate",     "api_call",     "CIS FortiOS 7.2",         "1", "FortiLog / FortiAnalyzer"),
    ("network", "f5",          "F5 BIG-IP",              "api_call",     "CIS F5 BIG-IP 16",        "1", "BIG-IP syslog / ASM"),
    ("network", "check_point", "Check Point NGFW",       "api_call",     "CIS Check Point R81",     "1", "SmartLog syslog"),
    ("network", "sophos",      "Sophos XG Firewall",     "api_call",     "CIS Sophos XG 18.5",      "1", "Sophos Central syslog"),
    ("network", "juniper",     "Juniper Junos",          "netconf_rpc",  "CIS Juniper Junos 21",    "1", "syslog structured format"),

    # --- WEB SERVER ---
    ("web_server", "apache_http", "Apache HTTP Server", "ssh_config_parse", "CIS Apache HTTP 2.4",     "1", "access_log, error_log"),
    ("web_server", "tomcat",      "Apache Tomcat",      "ssh_config_parse", "CIS Apache Tomcat 10",    "1", "catalina.log, access_log"),
    ("web_server", "nginx",       "NGINX",              "ssh_config_parse", "CIS NGINX 1.24",          "1", "access.log, error.log"),
    ("web_server", "iis",         "Microsoft IIS",      "ssh_config_parse", "CIS IIS 10",              "1", "IIS logs, Event Viewer"),
    ("web_server", "websphere",   "IBM WebSphere",      "api_call",         "CIS WebSphere 9.0",       "1", "SystemOut.log, security audit"),

    # --- VIRTUALIZATION ---
    ("virtualization", "vmware_esxi", "VMware ESXi", "vmware_api", "CIS VMware ESXi 7.0", "1", "ESXi syslog, vCenter events"),

    # --- CONTAINER ---
    ("container", "docker", "Docker Engine", "docker_api", "CIS Docker 1.6", "1", "Docker daemon log"),

    # --- DEVOPS ---
    ("devops", "github", "GitHub",      "rest_api",  "CIS GitHub 1.0",  "1", "GitHub Audit Log"),
    ("devops", "gitlab", "GitLab",      "rest_api",  "CIS GitLab 15",   "1", "GitLab Audit Events API"),

    # --- COLLABORATION ---
    ("collaboration", "microsoft_365",    "Microsoft 365",    "graph_api",  "CIS Microsoft 365 3.0",       "1", "Unified Audit Log (Purview)"),
    ("collaboration", "google_workspace", "Google Workspace", "admin_sdk",  "CIS Google Workspace 1.2",    "1", "Admin Activity Reports API"),

    # --- DATA PLATFORM ---
    ("data_platform", "snowflake", "Snowflake", "sql_query", "CIS Snowflake Foundations 1.0", "1", "QUERY_HISTORY / ACCESS_HISTORY"),

    # --- MIDDLEWARE ---
    ("middleware", "dynamics_365", "Microsoft Dynamics 365", "dataverse_api", "CIS Dynamics 365 1.0",   "1", "Dataverse Audit Log"),
    ("middleware", "sharepoint",   "Microsoft SharePoint",   "rest_api",      "CIS SharePoint 2019 1.0", "1", "SharePoint Audit Log"),
]

# ── Discovery YAML template ────────────────────────────────────────────────────

DISC_TEMPLATE = """\
version: '1.0'
provider: technology
category: {category}
tech_type: {tech_id}
display_name: {display_name}
action_type: {action_type}
cis_benchmark: {cis_benchmark}
cis_section: '{cis_section}'

# ─── Authentication & Access ───────────────────────────────────────────────────
discovery:
  - discovery_id: {tech_id}.auth.local_accounts
    description: Enumerate local user accounts and privilege levels
    calls:
      - action: {action_type}
        target: auth.accounts
        save_as: accounts
    emit:
      as: items
      items: "{{{{ accounts }}}}"
      item:
        resource_uid: "{{{{ item.username or item.name or item.id }}}}"
        resource_type: {tech_id}.user_account
        username: "{{{{ item.username or item.name }}}}"
        is_admin: "{{{{ item.is_admin or item.privileged }}}}"
        last_login: "{{{{ item.last_login }}}}"

  - discovery_id: {tech_id}.auth.password_policy
    description: Retrieve password policy configuration
    calls:
      - action: {action_type}
        target: auth.password_policy
        save_as: policy
    emit:
      as: item
      item:
        resource_uid: "{tech_id}.password_policy"
        resource_type: {tech_id}.policy
        min_length: "{{{{ policy.min_length }}}}"
        require_complexity: "{{{{ policy.complexity_enabled }}}}"
        max_age_days: "{{{{ policy.max_age_days }}}}"

# ─── Logging & Auditing ────────────────────────────────────────────────────────
  - discovery_id: {tech_id}.logging.audit_config
    description: Retrieve audit/logging configuration
    calls:
      - action: {action_type}
        target: logging.audit_config
        save_as: audit_cfg
    emit:
      as: item
      item:
        resource_uid: "{tech_id}.audit_config"
        resource_type: {tech_id}.config
        audit_enabled: "{{{{ audit_cfg.enabled }}}}"
        log_destination: "{{{{ audit_cfg.destination }}}}"
        log_level: "{{{{ audit_cfg.level }}}}"

# ─── Encryption & Transport ────────────────────────────────────────────────────
  - discovery_id: {tech_id}.encryption.transport
    description: Check transport encryption (TLS/SSL) configuration
    calls:
      - action: {action_type}
        target: encryption.transport
        save_as: tls_cfg
    emit:
      as: item
      item:
        resource_uid: "{tech_id}.transport_encryption"
        resource_type: {tech_id}.config
        tls_enabled: "{{{{ tls_cfg.enabled }}}}"
        tls_version: "{{{{ tls_cfg.min_version }}}}"
        cert_path: "{{{{ tls_cfg.cert_path }}}}"

# ─── Access Controls ──────────────────────────────────────────────────────────
  - discovery_id: {tech_id}.acl.admin_privileges
    description: Identify accounts with administrative or superuser privileges
    calls:
      - action: {action_type}
        target: acl.admin_accounts
        save_as: admins
    emit:
      as: items
      items: "{{{{ admins }}}}"
      item:
        resource_uid: "{{{{ item.username or item.name }}}}"
        resource_type: {tech_id}.privileged_account
        username: "{{{{ item.username or item.name }}}}"
        privilege_level: "{{{{ item.role or item.level }}}}"
"""

# ── Check rule YAML template ───────────────────────────────────────────────────

CHECK_TEMPLATE = """\
# {display_name} — CIS Check Rules
# Source benchmark: {cis_benchmark}
# Fill in rules per sprint. Each rule maps to a discovery_id above.

tech_type: {tech_id}
category: {category}
cis_benchmark: {cis_benchmark}

rules:
  - rule_id: {tech_id}.cis.auth.password_policy_min_length
    title: "Ensure minimum password length is configured"
    severity: medium
    cis_section: '{cis_section}'
    nist_controls: [IA-5]
    soc2_criteria: [CC6.1]
    scope: {tech_id}.auth.password_policy
    assertion:
      field: min_length
      operator: gte
      expected: 14
    remediation: >
      Configure minimum password length to 14+ characters in the {display_name}
      password policy settings.

  - rule_id: {tech_id}.cis.logging.audit_enabled
    title: "Ensure audit logging is enabled"
    severity: high
    cis_section: '{cis_section}'
    nist_controls: [AU-2, AU-3]
    soc2_criteria: [CC7.2]
    scope: {tech_id}.logging.audit_config
    assertion:
      field: audit_enabled
      operator: equals
      expected: "true"
    remediation: >
      Enable audit logging in {display_name} configuration.
      Refer to {cis_benchmark} for specific settings.

  - rule_id: {tech_id}.cis.encryption.tls_enabled
    title: "Ensure TLS/SSL is enabled for all connections"
    severity: high
    cis_section: '{cis_section}'
    nist_controls: [SC-8, SC-28]
    soc2_criteria: [CC6.7]
    scope: {tech_id}.encryption.transport
    assertion:
      field: tls_enabled
      operator: equals
      expected: "true"
    remediation: >
      Enable TLS/SSL encryption for {display_name} connections.
      Refer to {cis_benchmark} for minimum TLS version requirements.

  - rule_id: {tech_id}.cis.acl.admin_count
    title: "Ensure the number of administrative accounts is minimized"
    severity: medium
    cis_section: '{cis_section}'
    nist_controls: [AC-6]
    soc2_criteria: [CC6.3]
    scope: {tech_id}.acl.admin_privileges
    assertion:
      field: row_count
      operator: lte
      expected: 3
    remediation: >
      Review and reduce administrative accounts in {display_name}.
      Apply principle of least privilege.
"""

# ── CIEM rule YAML template ────────────────────────────────────────────────────

CIEM_TEMPLATE = """\
# {display_name} — CIEM Detection Rules
# Real-time authentication & access event analysis
# Log source: {log_source}

tech_type: {tech_id}
category: {category}
log_source: {log_source}

rules:
  - rule_id: tciem.{tech_id}.brute_force_login
    title: "Detect brute force login attempts"
    severity: high
    mitre_technique: T1110
    mitre_tactic: credential_access
    detection:
      event_type: authentication_failure
      threshold: 5
      window_seconds: 300
      group_by: [source_ip, username]
    evidence_fields: [source_ip, username, failure_count, first_attempt, last_attempt]
    response: alert

  - rule_id: tciem.{tech_id}.successful_login_after_failures
    title: "Detect successful login after repeated failures (possible credential stuffing)"
    severity: high
    mitre_technique: T1078
    mitre_tactic: initial_access
    detection:
      event_type: authentication_success
      preceded_by:
        event_type: authentication_failure
        min_count: 3
        window_seconds: 600
      group_by: [source_ip, username]
    evidence_fields: [source_ip, username, failure_count, success_time]
    response: alert

  - rule_id: tciem.{tech_id}.admin_privilege_grant
    title: "Detect privilege escalation or admin role grant"
    severity: critical
    mitre_technique: T1068
    mitre_tactic: privilege_escalation
    detection:
      event_type: privilege_change
      filters:
        action_in: [GRANT, ROLE_ADD, ELEVATION]
        target_privilege_in: [admin, superuser, root, DBA, wheel]
    evidence_fields: [actor, target_user, privilege_granted, timestamp]
    response: alert

  - rule_id: tciem.{tech_id}.off_hours_access
    title: "Detect access outside business hours (22:00–06:00 UTC)"
    severity: medium
    mitre_technique: T1078
    mitre_tactic: initial_access
    detection:
      event_type: authentication_success
      time_condition:
        utc_hour_not_in: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
      filters:
        account_type: human
    evidence_fields: [username, source_ip, login_time_utc]
    response: alert
"""

# ── Generator ─────────────────────────────────────────────────────────────────

def slugify(s: str) -> str:
    return s.lower().replace(" ", "_").replace("/", "_").replace("-", "_")


def generate_discovery(tech: tuple, apply: bool) -> List[str]:
    category, tech_id, display_name, action_type, cis_benchmark, cis_section, log_source = tech
    folder = DISC_ROOT / category / tech_id
    path = folder / "step6_discovery.yaml"

    content = DISC_TEMPLATE.format(
        category=category,
        tech_id=tech_id,
        display_name=display_name,
        action_type=action_type,
        cis_benchmark=cis_benchmark,
        cis_section=cis_section,
    )
    if apply:
        folder.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            return [f"  WRITE  {path.relative_to(CATALOG_ROOT)}"]
        return [f"  SKIP   {path.relative_to(CATALOG_ROOT)} (exists)"]
    return [f"  WOULD  {path.relative_to(CATALOG_ROOT)}"]


def generate_check_rule(tech: tuple, apply: bool) -> List[str]:
    category, tech_id, display_name, _, cis_benchmark, cis_section, _ = tech
    folder = RULE_ROOT / f"{category}_rule_check" / tech_id
    path = folder / f"{tech_id}_cis_rules.yaml"

    content = CHECK_TEMPLATE.format(
        category=category,
        tech_id=tech_id,
        display_name=display_name,
        cis_benchmark=cis_benchmark,
        cis_section=cis_section,
    )
    if apply:
        folder.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            return [f"  WRITE  {path.relative_to(CATALOG_ROOT)}"]
        return [f"  SKIP   {path.relative_to(CATALOG_ROOT)} (exists)"]
    return [f"  WOULD  {path.relative_to(CATALOG_ROOT)}"]


def generate_ciem_rule(tech: tuple, apply: bool) -> List[str]:
    category, tech_id, display_name, _, cis_benchmark, cis_section, log_source = tech
    folder = RULE_ROOT / f"{category}_rule_ciem" / tech_id
    path = folder / f"{tech_id}_ciem_rules.yaml"

    content = CIEM_TEMPLATE.format(
        category=category,
        tech_id=tech_id,
        display_name=display_name,
        log_source=log_source,
    )
    if apply:
        folder.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            return [f"  WRITE  {path.relative_to(CATALOG_ROOT)}"]
        return [f"  SKIP   {path.relative_to(CATALOG_ROOT)} (exists)"]
    return [f"  WOULD  {path.relative_to(CATALOG_ROOT)}"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate technology catalog YAML stubs")
    parser.add_argument("--apply", action="store_true", help="Write files (default: dry-run)")
    parser.add_argument("--category", default=None, help="Limit to one category")
    args = parser.parse_args()

    techs = TECHNOLOGIES
    if args.category:
        techs = [t for t in TECHNOLOGIES if t[0] == args.category]

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"\n{'='*60}")
    print(f"  Technology Catalog Generator — {mode}")
    print(f"  Technologies: {len(techs)}")
    print(f"{'='*60}\n")

    disc_count = check_count = ciem_count = 0
    for tech in techs:
        category, tech_id = tech[0], tech[1]
        print(f"  [{category}/{tech_id}]")
        for line in generate_discovery(tech, args.apply):
            print(line); disc_count += 1
        for line in generate_check_rule(tech, args.apply):
            print(line); check_count += 1
        for line in generate_ciem_rule(tech, args.apply):
            print(line); ciem_count += 1

    print(f"\n{'='*60}")
    print(f"  Discovery YAMLs : {disc_count}")
    print(f"  Check Rule YAMLs: {check_count}")
    print(f"  CIEM Rule YAMLs : {ciem_count}")
    print(f"  Total files     : {disc_count + check_count + ciem_count}")
    print(f"{'='*60}\n")
    if not args.apply:
        print("  ↑  Dry run. Pass --apply to write files.\n")


if __name__ == "__main__":
    main()
