"""
bootstrap_threat_flags.py — Phase 1 of the threat_flags catalog sprint.

Reads every rule_id from rule_metadata and applies the same keyword logic
used by FlagMapper to derive threat_flags values. Writes the result back
to rule_metadata.threat_flags as a JSONB array.

This is a one-shot bootstrap. After this runs, FlagMapper switches to
DB-driven lookups. Human QA should review the output CSV before production.

Usage:
    # Dry-run (prints report, writes nothing):
    python scripts/bootstrap_threat_flags.py --dry-run

    # Apply (writes to DB):
    python scripts/bootstrap_threat_flags.py --apply

    # Also write a QA CSV report:
    python scripts/bootstrap_threat_flags.py --apply --report /tmp/threat_flags_qa.csv

Env vars required (same as FlagMapper / check engine):
    CHECK_DB_HOST, CHECK_DB_PORT, CHECK_DB_NAME, CHECK_DB_USER, CHECK_DB_PASSWORD
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import psycopg2

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

# ── Keyword sets — authoritative copy (kept in sync with FlagMapper) ──────────
# IMPORTANT: these are derived ONLY from the check rule IDs we already have.
# Do NOT add keywords invented by an LLM — only keywords validated against
# real rule_id values in the catalog.

_FLAG_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "internet_exposed": (
        "internet_ingress",
        "not_publicly_accessible",
        "url_public",
        "unrestricted_access",
        "publicly_accessible",
        "public_access_configured",
        "no_public_ip",
        "cifs_unrestricted",
        "master_nodes_no_public_ip",
        "internet_ingress_all_ports",
        "internet_ingress_high_risk",
        "public_network_access",
        "network_access_default_deny",
        "external_ip",
        "publicly_accessible_gcp",
        "internet_access_restricted",
    ),
    "is_admin_role": (
        "admin_star",
        "privilege_escalation",
        "no_cluster_admin",
        "no_instance_profile_with_admin",
        "root_access",
        "full_admin",
        "no_admin_to_authenticated",
        "no_owner_subscription",
        "no_co_administrator",
        "no_primitive_role",
        "cluster_admin_binding",
    ),
    "has_imdsv1": (
        "imdsv2_enabled",
        "imds_v2_required",
        "metadata_service_v1",
    ),
    "has_no_mfa": (
        "mfa_enabled",
        "without_mfa",
        "mfa_not_enabled",
        "mfa_required",
        "mfa_configured",
        "two_factor",
        "two_step_verification",
        "multi_factor",
    ),
    "has_stale_credentials": (
        "access_keys_rotated",
        "access_key_age",
        "key_rotation_90",
        "access_key_rotation",
        "credential_rotation",
        "key_expiry",
        "service_account_key_age",
    ),
    "has_no_audit_trail": (
        "cloudtrail",
        "audit_log_enabled",
        "audit_logging",
        "activity_log_enabled",
        "diagnostic_setting_enabled",
        "audit_log",
        "gcp_audit",
        "audit_enabled",
        "action_trail",
    ),
    "has_no_rotation": (
        "rotation_enabled",
        "key_rotation",
        "auto_rotation",
        "rotation_policy",
        "automatic_rotation",
    ),
    "has_privileged_container": (
        "privileged_container",
        "privileged_pod",
        "hostpid",
        "host_pid",
        "privileged_contexts_denied",
        "no_privileged",
        "privileged_mode",
        "host_namespace",
    ),
}

# All valid flag names
ALL_FLAGS: List[str] = list(_FLAG_KEYWORDS.keys())


def compute_flags(rule_id: str) -> List[str]:
    """Return list of threat_flags that apply to this rule_id."""
    rid = rule_id.lower()
    flags = []
    for flag, keywords in _FLAG_KEYWORDS.items():
        if any(kw in rid for kw in keywords):
            flags.append(flag)
    return flags


def _connect() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["CHECK_DB_HOST"],
        port=int(os.environ.get("CHECK_DB_PORT", 5432)),
        dbname=os.environ["CHECK_DB_NAME"],
        user=os.environ["CHECK_DB_USER"],
        password=os.environ["CHECK_DB_PASSWORD"],
    )


def run(dry_run: bool, report_path: str | None) -> None:
    logger.info("Connecting to check DB (%s/%s)…",
                os.environ["CHECK_DB_HOST"], os.environ["CHECK_DB_NAME"])
    conn = _connect()
    cur = conn.cursor()

    # Read all rule_ids (and their existing threat_flags if any)
    cur.execute(
        "SELECT rule_id, provider, threat_flags FROM rule_metadata ORDER BY rule_id"
    )
    rows = cur.fetchall()
    logger.info("Loaded %d rules from rule_metadata.", len(rows))

    # Compute flags per rule
    by_flag: Dict[str, List[str]] = defaultdict(list)
    updates: List[Tuple[str, str]] = []   # (rule_id, flags_json)
    skipped_already_set = 0

    for rule_id, provider, existing_flags in rows:
        if existing_flags and existing_flags not in ([], "[]", None):
            # Already has flags — don't overwrite (manual QA may have set them)
            skipped_already_set += 1
            continue

        flags = compute_flags(rule_id)
        if flags:
            for f in flags:
                by_flag[f].append(rule_id)
            updates.append((rule_id, json.dumps(flags)))

    # Stats
    total_flagged = len(updates)
    total_rules = len(rows)
    logger.info("Flagged %d / %d rules (%d already had flags — skipped).",
                total_flagged, total_rules, skipped_already_set)
    for flag in ALL_FLAGS:
        count = len(by_flag[flag])
        sample = by_flag[flag][:3]
        logger.info("  %-30s  %4d rules   sample: %s", flag, count, sample)

    unflagged = total_rules - total_flagged - skipped_already_set
    logger.info("  %-30s  %4d rules (no threat signal — normal for most config rules)",
                "unflagged", unflagged)

    # Write QA report
    if report_path:
        _write_report(report_path, rows, by_flag, updates)
        logger.info("QA report written to %s", report_path)

    # Apply or dry-run
    if dry_run:
        logger.info("DRY-RUN — no writes performed. Re-run with --apply to commit.")
        cur.close()
        conn.close()
        return

    logger.info("Applying %d updates to rule_metadata.threat_flags…", len(updates))
    batch_size = 500
    for i in range(0, len(updates), batch_size):
        batch = updates[i:i + batch_size]
        # Use executemany for bulk update
        cur.executemany(
            "UPDATE rule_metadata SET threat_flags = %s::jsonb WHERE rule_id = %s",
            [(flags_json, rule_id) for rule_id, flags_json in batch],
        )
        conn.commit()
        logger.info("  Committed batch %d-%d.", i, i + len(batch))

    logger.info("Bootstrap complete. %d rules updated.", len(updates))
    cur.close()
    conn.close()


def _write_report(
    path: str,
    rows: list,
    by_flag: Dict[str, List[str]],
    updates: list,
) -> None:
    """Write a CSV for human QA review."""
    updates_map = {rule_id: flags_json for rule_id, flags_json in updates}

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rule_id", "provider", "computed_flags",
            "internet_exposed", "is_admin_role", "has_imdsv1",
            "has_no_mfa", "has_stale_credentials",
            "has_no_audit_trail", "has_no_rotation",
            "has_privileged_container",
        ])
        for rule_id, provider, existing_flags in rows:
            flags = json.loads(updates_map.get(rule_id, "[]"))
            writer.writerow([
                rule_id,
                provider or "",
                json.dumps(flags),
                "1" if "internet_exposed" in flags else "",
                "1" if "is_admin_role" in flags else "",
                "1" if "has_imdsv1" in flags else "",
                "1" if "has_no_mfa" in flags else "",
                "1" if "has_stale_credentials" in flags else "",
                "1" if "has_no_audit_trail" in flags else "",
                "1" if "has_no_rotation" in flags else "",
                "1" if "has_privileged_container" in flags else "",
            ])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap rule_metadata.threat_flags")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true",
                       help="Print stats only, write nothing")
    group.add_argument("--apply", action="store_true",
                       help="Write threat_flags to DB")
    parser.add_argument("--report", metavar="CSV_PATH",
                        help="Write QA CSV to this path (works with both modes)")
    args = parser.parse_args()

    # Validate env
    for var in ("CHECK_DB_HOST", "CHECK_DB_NAME", "CHECK_DB_USER", "CHECK_DB_PASSWORD"):
        if not os.environ.get(var):
            logger.error("Missing env var: %s", var)
            sys.exit(1)

    run(dry_run=args.dry_run, report_path=args.report)
