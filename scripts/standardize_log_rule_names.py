#!/usr/bin/env python3
"""
standardize_log_rule_names.py

Standardizes log/correlation check rule IDs and populates service/resource fields.

FIX 1: Rules missing provider prefix (e.g. `iam.ct.add_user_to_group` → `aws.iam.cloudtrail.add_user_to_group`)
FIX 2: Rules with correct rule_id but empty service/resource fields (Azure, GCP, OCI, IBM rules)

Usage:
    python standardize_log_rule_names.py --dry-run   # preview changes
    python standardize_log_rule_names.py              # apply changes
"""

import argparse
import sys
import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port": 5432,
    "dbname": "threat_engine_check",
    "user": "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# Maps: (domain_prefix, log_source_type) → (new_rule_id_prefix, service, resource)
PREFIX_MAP = {
    # CloudTrail domain groups → aws.{domain}.cloudtrail.{check}
    ("iam",       "cloudtrail"):  ("aws.iam",       "iam",       "cloudtrail"),
    ("storage",   "cloudtrail"):  ("aws.storage",   "storage",   "cloudtrail"),
    ("compute",   "cloudtrail"):  ("aws.compute",   "compute",   "cloudtrail"),
    ("netsec",    "cloudtrail"):  ("aws.netsec",    "netsec",    "cloudtrail"),
    ("secsvc",    "cloudtrail"):  ("aws.secsvc",    "secsvc",    "cloudtrail"),
    ("paas",      "cloudtrail"):  ("aws.paas",      "paas",      "cloudtrail"),
    ("devops",    "cloudtrail"):  ("aws.devops",    "devops",    "cloudtrail"),
    ("monitor",   "cloudtrail"):  ("aws.monitor",   "monitor",   "cloudtrail"),
    ("threat",    "cloudtrail"):  ("aws.threat",    "threat",    "cloudtrail"),
    ("ciem",      "cloudtrail"):  ("aws.ciem",      "ciem",      "cloudtrail"),
    ("datasec",   "cloudtrail"):  ("aws.datasec",   "datasec",   "cloudtrail"),
    ("container", "cloudtrail"):  ("aws.container", "container", "cloudtrail"),
    ("network",   "cloudtrail"):  ("aws.network",   "network",   "cloudtrail"),
    # Service-specific logs
    ("alb",        "alb"):        ("aws.alb",       "alb",       "alb_log"),
    ("cloudfront", "cloudfront"): ("aws.cloudfront","cloudfront","access_log"),
    ("dns",        "dns"):        ("aws.dns",       "dns",       "query_log"),
    ("lambda",     "lambda"):     ("aws.lambda",    "lambda",    "function_log"),
    ("s3",         "s3_access"):  ("aws.s3",        "s3",        "access_log"),
    ("rds",        "rds_audit"):  ("aws.rds",       "rds",       "audit_log"),
    ("waf",        "waf"):        ("aws.waf",       "waf",       "web_acl_log"),
    ("guardduty",  "guardduty"):  ("aws.guardduty", "guardduty", "finding"),
    ("eks",        "eks_audit"):  ("aws.eks",       "eks",       "audit_log"),
    ("vpc",        "vpc_flow"):   ("aws.vpc",       "vpc",       "flow_log"),
    ("network",    "vpc_flow"):   ("aws.network",   "network",   "flow_log"),
    # network.flow.* rules (log_source_type blank)
    ("network",    ""):           ("aws.network",   "network",   "flow_log"),
    # container.ct.* rules (log_source_type blank but .ct. in rule_id → CloudTrail)
    ("container",  "cloudtrail"): ("aws.container", "container", "cloudtrail"),
    ("container",  ""):           ("aws.container", "container", "cloudtrail"),
    # Correlation rules (no log_source_type)
    ("ciem",       ""):           ("aws.ciem",      "ciem",      "correlation"),
    ("datasec",    ""):           ("aws.datasec",   "datasec",   "correlation"),
    ("threat",     ""):           ("aws.threat",    "threat",    "correlation"),
}

# Maps: log_source_type → (service, resource) for FIX 2 (rules already have provider prefix)
SOURCE_SERVICE_MAP = {
    "azure_activity":  ("activity",  "activity_log"),
    "azure_aks_audit": ("aks",       "audit_log"),
    "azure_appgw":     ("appgw",     "appgw_log"),
    "azure_defender":  ("defender",  "finding"),
    "azure_function":  ("function",  "function_log"),
    "azure_keyvault":  ("keyvault",  "keyvault_log"),
    "azure_nsg_flow":  ("nsg",       "flow_log"),
    "azure_sql_audit": ("sql",       "audit_log"),
    "azure_storage":   ("storage",   "storage_log"),
    "gcp_audit":       ("audit",     "admin_activity"),
    "gcp_cloudsql":    ("cloudsql",  "audit_log"),
    "gcp_data_access": ("data",      "access_log"),
    "gcp_function":    ("function",  "function_log"),
    "gcp_gke_audit":   ("gke",       "audit_log"),
    "gcp_lb":          ("lb",        "access_log"),
    "gcp_scc":         ("scc",       "finding"),
    "gcp_vpc_flow":    ("vpc",       "flow_log"),
    "ibm_activity":    ("activity",  "activity_tracker"),
    "ibm_db_audit":    ("db",        "audit_log"),
    "ibm_k8s_audit":   ("k8s",       "audit_log"),
    "ibm_scc":         ("scc",       "finding"),
    "oci_audit":       ("audit",     "audit_log"),
    "oci_cloudguard":  ("cloudguard","finding"),
    "oci_db_audit":    ("db",        "audit_log"),
    "oci_oke_audit":   ("oke",       "audit_log"),
    "oci_vcn_flow":    ("vcn",       "flow_log"),
    "oci_waf":         ("waf",       "access_log"),
}

PROVIDER_PREFIXES = ("aws.", "gcp.", "azure.", "oci.", "ibm.")


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def build_new_rule_id(old_rule_id: str, domain: str, log_source_type: str) -> tuple[str, str, str] | None:
    """
    Given an old rule_id (without provider prefix), compute:
    (new_rule_id, service, resource)
    Returns None if no mapping found.
    """
    # Try exact match first
    key = (domain, log_source_type)
    if key not in PREFIX_MAP:
        # Try fallback with empty log_source_type
        key = (domain, "")
        if key not in PREFIX_MAP:
            return None

    new_prefix, service, resource = PREFIX_MAP[key]

    # Split old rule_id and drop the domain part
    parts = old_rule_id.split(".")
    if len(parts) < 2:
        return None

    # Remainder is everything after the domain
    remainder_parts = parts[1:]

    # Replace 'ct' abbreviation with 'cloudtrail' and 'flow' with 'flow_log'
    cleaned_parts = []
    for p in remainder_parts:
        if p == "ct":
            p = "cloudtrail"
        elif p == "flow" and resource == "flow_log":
            # Skip inserting 'flow' since resource already captures it
            p = "flow_log"
        cleaned_parts.append(p)

    # If the first cleaned part equals the resource, don't duplicate it
    if cleaned_parts and cleaned_parts[0] == resource:
        # Already has the resource component, use as-is after prefix
        new_rule_id = new_prefix + "." + ".".join(cleaned_parts)
    else:
        # Insert the resource component between prefix and check name
        new_rule_id = new_prefix + "." + resource + "." + ".".join(cleaned_parts)

    # Clean up any double dots
    while ".." in new_rule_id:
        new_rule_id = new_rule_id.replace("..", ".")

    return new_rule_id, service, resource


def fetch_fix1_rules(cur):
    """Fetch rules without provider prefix that are log/correlation type."""
    cur.execute("""
        SELECT rc.rule_id, rc.service, rm.log_source_type, rm.resource
        FROM rule_checks rc
        LEFT JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
        WHERE rc.check_type IN ('log', 'correlation')
          AND rc.is_active = true
          AND rc.rule_id NOT LIKE 'aws.%%'
          AND rc.rule_id NOT LIKE 'gcp.%%'
          AND rc.rule_id NOT LIKE 'azure.%%'
          AND rc.rule_id NOT LIKE 'oci.%%'
          AND rc.rule_id NOT LIKE 'ibm.%%'
        ORDER BY rc.rule_id
    """)
    return cur.fetchall()


def fetch_fix2_rules(cur):
    """Fetch rules with provider prefix but missing service/resource fields."""
    cur.execute("""
        SELECT rc.rule_id, rc.service, rm.log_source_type, rm.resource
        FROM rule_checks rc
        LEFT JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
        WHERE rc.check_type IN ('log', 'correlation')
          AND rc.is_active = true
          AND (
            rc.rule_id LIKE 'aws.%%'
            OR rc.rule_id LIKE 'gcp.%%'
            OR rc.rule_id LIKE 'azure.%%'
            OR rc.rule_id LIKE 'oci.%%'
            OR rc.rule_id LIKE 'ibm.%%'
          )
          AND (rc.service IS NULL OR rc.service = '')
        ORDER BY rc.rule_id
    """)
    return cur.fetchall()


def run_verification(cur):
    """Run verification query and return results."""
    cur.execute("""
        SELECT
          CASE
            WHEN rc.rule_id NOT LIKE 'aws.%%' AND rc.rule_id NOT LIKE 'gcp.%%'
              AND rc.rule_id NOT LIKE 'azure.%%' AND rc.rule_id NOT LIKE 'oci.%%'
              AND rc.rule_id NOT LIKE 'ibm.%%' THEN 'STILL_MISSING_PROVIDER'
            WHEN (rc.service IS NULL OR rc.service = '') THEN 'STILL_MISSING_SERVICE'
            ELSE 'OK'
          END as status,
          COUNT(*) as cnt
        FROM rule_checks rc
        WHERE rc.check_type IN ('log','correlation') AND rc.is_active = true
        GROUP BY 1
        ORDER BY 1
    """)
    return cur.fetchall()


def main():
    parser = argparse.ArgumentParser(description="Standardize log/correlation rule names")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    args = parser.parse_args()

    dry_run = args.dry_run
    if dry_run:
        print("=== DRY RUN MODE — no changes will be applied ===\n")
    else:
        print("=== LIVE MODE — changes will be applied ===\n")

    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ── Before counts ────────────────────────────────────────────────────────
    print("── BEFORE STATE ──────────────────────────────────────────────────")
    before_rows = run_verification(cur)
    for row in before_rows:
        print(f"  {row['status']:<30} {row['cnt']}")
    print()

    # ── FIX 1 ────────────────────────────────────────────────────────────────
    print("── FIX 1: Rules missing provider prefix ──────────────────────────")
    fix1_rules = fetch_fix1_rules(cur)
    print(f"  Found {len(fix1_rules)} rules to fix\n")

    fix1_applied = 0
    fix1_skipped = 0
    fix1_skipped_details = []

    for row in fix1_rules:
        old_rule_id = row["rule_id"]
        log_source_type = (row["log_source_type"] or "").strip()
        domain = old_rule_id.split(".")[0]

        result = build_new_rule_id(old_rule_id, domain, log_source_type)
        if result is None:
            fix1_skipped += 1
            fix1_skipped_details.append(
                f"  SKIP (no mapping): rule_id={old_rule_id!r}, domain={domain!r}, source={log_source_type!r}"
            )
            continue

        new_rule_id, service, resource = result
        print(f"  {old_rule_id}")
        print(f"    → {new_rule_id}  [service={service}, resource={resource}]")

        if not dry_run:
            # Update rule_metadata first (rule_id + resource)
            cur.execute(
                "UPDATE rule_metadata SET rule_id = %s, resource = %s WHERE rule_id = %s",
                (new_rule_id, resource, old_rule_id),
            )
            # Update rule_checks (rule_id + service)
            cur.execute(
                "UPDATE rule_checks SET rule_id = %s, service = %s WHERE rule_id = %s",
                (new_rule_id, service, old_rule_id),
            )

        fix1_applied += 1

    if fix1_skipped_details:
        print(f"\n  Skipped {fix1_skipped} rules (no mapping found):")
        for d in fix1_skipped_details:
            print(d)

    print(f"\n  FIX 1 summary: {fix1_applied} renamed, {fix1_skipped} skipped\n")

    # ── FIX 2 ────────────────────────────────────────────────────────────────
    print("── FIX 2: Rules with correct rule_id but empty service/resource ───")
    fix2_rules = fetch_fix2_rules(cur)
    print(f"  Found {len(fix2_rules)} rules to fix\n")

    fix2_applied = 0
    fix2_skipped = 0
    fix2_skipped_details = []

    for row in fix2_rules:
        rule_id = row["rule_id"]
        log_source_type = (row["log_source_type"] or "").strip()

        if log_source_type not in SOURCE_SERVICE_MAP:
            fix2_skipped += 1
            fix2_skipped_details.append(
                f"  SKIP (no mapping): rule_id={rule_id!r}, source={log_source_type!r}"
            )
            continue

        service, resource = SOURCE_SERVICE_MAP[log_source_type]
        print(f"  {rule_id}")
        print(f"    → service={service}, resource={resource}  (source={log_source_type})")

        if not dry_run:
            # Update rule_metadata resource
            cur.execute(
                "UPDATE rule_metadata SET resource = %s WHERE rule_id = %s",
                (resource, rule_id),
            )
            # Update rule_checks service
            cur.execute(
                "UPDATE rule_checks SET service = %s WHERE rule_id = %s",
                (service, rule_id),
            )

        fix2_applied += 1

    if fix2_skipped_details:
        print(f"\n  Skipped {fix2_skipped} rules (no mapping found):")
        for d in fix2_skipped_details:
            print(d)

    print(f"\n  FIX 2 summary: {fix2_applied} updated, {fix2_skipped} skipped\n")

    # ── Commit or rollback ───────────────────────────────────────────────────
    if not dry_run:
        conn.commit()
        print("Changes committed to database.\n")
    else:
        conn.rollback()
        print("Dry run complete — no changes committed.\n")

    # ── After counts (re-fetch after commit) ─────────────────────────────────
    print("── AFTER STATE ───────────────────────────────────────────────────")
    after_rows = run_verification(cur)
    for row in after_rows:
        print(f"  {row['status']:<30} {row['cnt']}")

    print()
    print("── SUMMARY ───────────────────────────────────────────────────────")
    print(f"  FIX 1 (renamed):  {fix1_applied} rules  ({fix1_skipped} skipped)")
    print(f"  FIX 2 (enriched): {fix2_applied} rules  ({fix2_skipped} skipped)")
    print(f"  Mode: {'DRY RUN (no changes applied)' if dry_run else 'LIVE (changes applied)'}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
