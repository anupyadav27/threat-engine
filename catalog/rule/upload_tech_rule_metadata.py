#!/usr/bin/env python3
"""
upload_tech_rule_metadata.py
=============================
Upload all generated CIS technology rule metadata into the tech_rule_metadata
and tech_rule_control_mapping tables.

Sources:
  catalog/rule/{category}_rule_metadata/{tech}/{tech}_metadata.yaml

Covers all 8 sprints:
  database:      postgresql, mysql, oracle_db, ibm_db2, sql_server, mariadb, mongodb, cassandra
  linux:         ubuntu, debian, rhel, suse, centos
  networking:    cisco_ios_xe, palo_alto, cisco_asa, check_point, cisco_ios_xr, cisco_nxos,
                 fortigate, cisco_firewall
  web_server:    apache_http, nginx, iis, tomcat, websphere
  container:     docker
  virtualization: vmware_esxi
  devops:        gitlab
  data:          snowflake
  cloud_saas:    microsoft_365, google_workspace, sharepoint, dynamics_365

Usage:
  python upload_tech_rule_metadata.py --dry-run        # count only, no DB writes
  python upload_tech_rule_metadata.py                  # upload all
  python upload_tech_rule_metadata.py --category database linux
  python upload_tech_rule_metadata.py --tech postgresql mysql
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import Json, execute_values
import yaml

ROOT     = Path(__file__).resolve().parents[2]
RULE_DIR = ROOT / "catalog" / "rule"

CATEGORY_DIRS = [
    "database_rule_metadata",
    "linux_rule_metadata",
    "networking_rule_metadata",
    "web_server_rule_metadata",
    "container_rule_metadata",
    "virtualization_rule_metadata",
    "devops_rule_metadata",
    "data_rule_metadata",
    "cloud_saas_rule_metadata",
    "middleware_rule_metadata",
]


def _db_conn() -> Any:
    return psycopg2.connect(
        host     = os.environ.get("TECH_DB_HOST",     os.environ.get("DISCOVERIES_DB_HOST", "localhost")),
        port     = int(os.environ.get("TECH_DB_PORT", os.environ.get("DISCOVERIES_DB_PORT", "5432"))),
        dbname   = os.environ.get("TECH_DB_NAME",     "threat_engine_tech"),
        user     = os.environ.get("TECH_DB_USER",     os.environ.get("DISCOVERIES_DB_USER", "postgres")),
        password = os.environ.get("TECH_DB_PASSWORD", os.environ.get("DISCOVERIES_DB_PASSWORD", "")),
        connect_timeout = 10,
    )


def _collect_metadata_files(
    category_filter: Optional[List[str]],
    tech_filter: Optional[List[str]],
) -> List[Path]:
    files: List[Path] = []
    for cat_dir_name in CATEGORY_DIRS:
        cat_dir = RULE_DIR / cat_dir_name
        if not cat_dir.exists():
            continue
        for tech_dir in sorted(cat_dir.iterdir()):
            if not tech_dir.is_dir():
                continue
            if tech_filter and tech_dir.name not in tech_filter:
                continue
            # Derive category from dir name (strip _rule_metadata suffix)
            category = cat_dir_name.replace("_rule_metadata", "")
            if category_filter and category not in category_filter:
                continue
            for yaml_file in sorted(tech_dir.glob("*_metadata.yaml")):
                files.append(yaml_file)
    return files


def _parse_metadata_file(path: Path) -> List[Dict[str, Any]]:
    with path.open() as f:
        doc = yaml.safe_load(f) or {}
    return doc.get("rules", [])


def _upsert_rules(
    conn: Any,
    rules: List[Dict[str, Any]],
    dry_run: bool,
) -> int:
    if not rules:
        return 0

    metadata_rows = []
    mapping_rows  = []

    for rule in rules:
        rule_id = rule.get("rule_id", "").strip()
        if not rule_id:
            continue

        nist = rule.get("nist_controls") or []
        if isinstance(nist, str):
            nist = [nist]
        soc2 = rule.get("soc2_criteria") or []
        if isinstance(soc2, str):
            soc2 = [soc2]

        metadata_rows.append((
            rule_id,
            rule.get("tech_type",    ""),
            rule.get("category",     ""),
            (rule.get("title", "") or "")[:500],
            (rule.get("severity", "medium") or "medium").lower(),
            rule.get("cis_benchmark", ""),
            rule.get("cis_section",   ""),
            Json(nist),
            Json(soc2),
            rule.get("remediation", "") or rule.get("remediation_steps", "") or "",
            Json({
                "automation_type":      rule.get("automation_type", ""),
                "profile_applicability": rule.get("profile_applicability", ""),
                "cis_control":          rule.get("cis_control", ""),
                "cis_version":          rule.get("cis_version", ""),
                "description":          (rule.get("description", "") or "")[:2000],
                "rationale":            (rule.get("rationale", "") or "")[:2000],
                "references":           rule.get("references", []) or [],
            }),
        ))

        # CIS framework mapping
        cis_bench = rule.get("cis_benchmark", "")
        cis_ctrl  = rule.get("cis_control", "")
        if cis_bench and cis_ctrl:
            mapping_rows.append((
                rule_id,
                cis_bench.lower().replace(" ", "_"),
                cis_ctrl,
                rule.get("title", "")[:500],
            ))

    if dry_run:
        return len(metadata_rows)

    with conn.cursor() as cur:
        execute_values(
            cur,
            """
            INSERT INTO tech_rule_metadata
                (rule_id, tech_type, tech_category, title, severity,
                 cis_benchmark, cis_section, nist_controls, soc2_criteria,
                 remediation, rule_metadata)
            VALUES %s
            ON CONFLICT (rule_id) DO UPDATE SET
                title        = EXCLUDED.title,
                severity     = EXCLUDED.severity,
                cis_benchmark = EXCLUDED.cis_benchmark,
                cis_section  = EXCLUDED.cis_section,
                nist_controls = EXCLUDED.nist_controls,
                soc2_criteria = EXCLUDED.soc2_criteria,
                remediation  = EXCLUDED.remediation,
                rule_metadata = EXCLUDED.rule_metadata
            """,
            metadata_rows,
        )
        if mapping_rows:
            execute_values(
                cur,
                """
                INSERT INTO tech_rule_control_mapping
                    (rule_id, framework, control_id, control_name)
                VALUES %s
                ON CONFLICT (rule_id, framework, control_id) DO NOTHING
                """,
                mapping_rows,
            )

    conn.commit()
    return len(metadata_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload tech rule metadata to DB")
    parser.add_argument("--dry-run",   action="store_true", help="Count only, no DB writes")
    parser.add_argument("--category",  nargs="+", help="Filter by category (e.g. database linux)")
    parser.add_argument("--tech",      nargs="+", help="Filter by tech (e.g. postgresql mysql)")
    args = parser.parse_args()

    files = _collect_metadata_files(args.category, args.tech)
    if not files:
        print("No metadata files found matching filters.")
        sys.exit(0)

    print(f"Found {len(files)} metadata file(s).")

    conn = None if args.dry_run else _db_conn()

    total_rules = 0
    total_files = 0
    for path in files:
        rules = _parse_metadata_file(path)
        if not rules:
            continue
        count = _upsert_rules(conn, rules, dry_run=args.dry_run)
        label = "would upload" if args.dry_run else "uploaded"
        print(f"  {path.parent.name}/{path.name}: {label} {count} rules")
        total_rules += count
        total_files += 1

    if conn:
        conn.close()

    action = "Would upload" if args.dry_run else "Uploaded"
    print(f"\n{action} {total_rules} rules from {total_files} files.")


if __name__ == "__main__":
    main()
