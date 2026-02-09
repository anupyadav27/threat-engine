#!/usr/bin/env python3
"""
Enrich compliance_controls table with data from CIS/NIST/PCI JSON files.

Fills in:
  - testing_procedures    (from audit steps)
  - implementation_guidance (from remediation steps)
  - severity              (derived from profile level or control type)
  - control_description   (if empty, from JSON description)
  - control_data JSONB    (merge: rationale, default_value, impact, profile,
                           assessment_type, references)

Only updates controls that ALREADY EXIST in the DB (no new inserts).
Matches by control_number (DB) == id (JSON).
"""

import argparse
import json
import glob
import os
import sys
import re

# ---------------------------------------------------------------------------
# JSON source configuration
# ---------------------------------------------------------------------------
BASE = "/Users/apple/Desktop/compliance_Database/compliance_document"

# Map framework_id → list of JSON file paths (order = priority, last wins)
FRAMEWORK_JSON_MAP = {
    "cis_aws": [
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_Amazon_Web_Services_Foundations_Benchmark_v4.0.1.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_Amazon_Web_Services_Foundations_Benchmark_v5.0.0.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_AWS_Compute_Services_Benchmark_v1.1.0.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_AWS_Database_Services_Benchmark_v1.0.0.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_AWS_End_User_Compute_Services_Benchmark_v1.2.0.json",
        f"{BASE}/cis/Cloud_Providers/AWS/output/CIS_AWS_Storage_Services_Benchmark_v1.0.0.json",
    ],
    "nist_800_53_rev5": [
        f"{BASE}/nist/NIST_SP_800-53_Rev5_controls.json",
    ],
    "pci_dss_v4": [
        f"{BASE}/pci/PCI_DSS_v4_0_1_controls.json",
    ],
}


def load_cis_json(filepath: str) -> dict:
    """Load CIS-format JSON → dict keyed by control id."""
    with open(filepath) as f:
        data = json.load(f)
    if not isinstance(data, list):
        return {}
    lookup = {}
    for rec in data:
        cid = rec.get("id")
        if cid:
            lookup[cid] = rec
    return lookup


def load_nist_json(filepath: str) -> dict:
    """Load NIST 800-53 JSON → dict keyed by control id (e.g. AC-2(1))."""
    with open(filepath) as f:
        data = json.load(f)
    if not isinstance(data, list):
        return {}
    lookup = {}
    for rec in data:
        cid = rec.get("id")
        if cid:
            # Normalize: JSON has "AC-1-a", DB has "AC-1-a" — direct match
            lookup[cid] = rec
    return lookup


def load_pci_json(filepath: str) -> dict:
    """Load PCI DSS JSON → dict keyed by control id (e.g. 1.1.1)."""
    with open(filepath) as f:
        data = json.load(f)
    if not isinstance(data, list):
        return {}
    lookup = {}
    for rec in data:
        cid = rec.get("id")
        if cid:
            lookup[cid] = rec
    return lookup


def derive_severity_from_profile(profile: str) -> str:
    """Derive severity from CIS profile level."""
    if not profile:
        return "medium"
    profile_lower = profile.lower()
    if "level 2" in profile_lower:
        return "high"
    elif "level 1" in profile_lower:
        return "medium"
    return "medium"


def build_cis_update(db_control_number: str, json_rec: dict) -> dict:
    """Build UPDATE fields from CIS JSON record."""
    update = {}

    # testing_procedures ← audit
    audit = json_rec.get("audit", "").strip()
    if audit and len(audit) > 10:
        update["testing_procedures"] = audit

    # implementation_guidance ← remediation
    remediation = json_rec.get("remediation", "").strip()
    if remediation and len(remediation) > 10:
        update["implementation_guidance"] = remediation

    # severity ← profile
    profile = json_rec.get("profile", "")
    update["severity"] = derive_severity_from_profile(profile)

    # control_description (only if richer than current)
    desc = json_rec.get("description", "").strip()
    if desc:
        update["description_candidate"] = desc

    # control_data merge fields
    extra_data = {}
    if json_rec.get("rationale", "").strip():
        extra_data["rationale"] = json_rec["rationale"].strip()
    if json_rec.get("default_value", "").strip():
        extra_data["default_value"] = json_rec["default_value"].strip()
    if json_rec.get("impact", "").strip() and json_rec["impact"].strip() != "N/A":
        extra_data["impact"] = json_rec["impact"].strip()
    if profile:
        extra_data["profile"] = profile.replace("\u2022 ", "").strip()
    assessment = json_rec.get("assessment", "").strip()
    if assessment:
        extra_data["assessment_type"] = assessment
    refs = json_rec.get("references_text", "").strip()
    if refs:
        extra_data["references_text"] = refs
    addl = json_rec.get("additional_information", "").strip()
    if addl:
        extra_data["additional_information"] = addl
    if extra_data:
        update["control_data_merge"] = extra_data

    return update


def build_nist_update(db_control_number: str, json_rec: dict) -> dict:
    """Build UPDATE fields from NIST 800-53 JSON record."""
    update = {}

    # NIST has: id, title, description, discussion, related_controls, source
    discussion = json_rec.get("discussion", "").strip()
    if discussion and len(discussion) > 10:
        update["testing_procedures"] = discussion

    desc = json_rec.get("description", "").strip()
    if desc and len(desc) > 10:
        update["implementation_guidance"] = desc

    # Derive severity from control family
    cid = json_rec.get("id", "")
    if any(cid.startswith(p) for p in ["AC-", "AU-", "IA-", "SC-"]):
        update["severity"] = "high"
    elif any(cid.startswith(p) for p in ["CM-", "SI-", "RA-", "CA-"]):
        update["severity"] = "medium"
    else:
        update["severity"] = "medium"

    extra_data = {}
    related = json_rec.get("related_controls", "")
    if isinstance(related, list):
        related = ", ".join(str(r) for r in related)
    elif isinstance(related, str):
        related = related.strip()
    if related:
        extra_data["related_controls"] = related
    if extra_data:
        update["control_data_merge"] = extra_data

    return update


def build_pci_update(db_control_number: str, json_rec: dict) -> dict:
    """Build UPDATE fields from PCI DSS JSON record."""
    update = {}

    desc = json_rec.get("description", "").strip()
    if desc and len(desc) > 10:
        update["description_candidate"] = desc
        # PCI descriptions often contain testing procedures
        update["implementation_guidance"] = desc
        # If description contains "Testing Procedures", use it for testing_procedures too
        if "testing procedure" in desc.lower():
            update["testing_procedures"] = desc

    # Derive severity from requirement number
    cid = json_rec.get("id", "")
    first = cid.split(".")[0] if cid else ""
    # PCI critical reqs: 1,2 (network), 3,4 (data), 7,8 (access)
    if first in ("1", "2", "3", "4", "7", "8"):
        update["severity"] = "high"
    else:
        update["severity"] = "medium"

    return update


def enrich_framework(conn, framework_id: str, json_files: list,
                     loader_fn, builder_fn, dry_run: bool) -> int:
    """Enrich controls for one framework. Returns count of updated rows."""
    # Load all JSON data (later files override earlier for same ID)
    json_lookup = {}
    for fpath in json_files:
        if not os.path.exists(fpath):
            print(f"  SKIP (not found): {os.path.basename(fpath)}")
            continue
        loaded = loader_fn(fpath)
        print(f"  Loaded {len(loaded):>5} controls from {os.path.basename(fpath)}")
        json_lookup.update(loaded)

    if not json_lookup:
        print(f"  No JSON data loaded for {framework_id}")
        return 0

    # Fetch DB controls for this framework
    with conn.cursor() as cur:
        cur.execute("""
            SELECT control_id, control_number, control_name,
                   control_description, control_data
            FROM compliance_controls
            WHERE framework_id = %s
        """, (framework_id,))
        db_controls = cur.fetchall()

    print(f"  DB controls: {len(db_controls)}")

    matched = 0
    updated = 0

    for row in db_controls:
        ctrl_id, ctrl_number, ctrl_name, ctrl_desc, ctrl_data = row
        ctrl_data = ctrl_data or {}

        # Try to match by control_number
        json_rec = json_lookup.get(ctrl_number)

        # Fallback: try normalized matching for NIST format differences
        if not json_rec and ctrl_number:
            # DB might have "AC-17(1)" and JSON has "AC-17(1)" — direct
            # Or DB has "AC-2(1)" and JSON has "AC-2(1)" — direct
            # Try stripping parentheses format: AC-17_1 → AC-17(1)
            alt = ctrl_number.replace("_", "(").rstrip(")") + ")" if "_" in ctrl_number else None
            if alt:
                json_rec = json_lookup.get(alt)

        if not json_rec:
            continue

        matched += 1
        updates = builder_fn(ctrl_number, json_rec)
        if not updates:
            continue

        # Build SQL SET clause
        set_parts = []
        params = []

        if "testing_procedures" in updates:
            set_parts.append("testing_procedures = %s")
            params.append(updates["testing_procedures"])

        if "implementation_guidance" in updates:
            set_parts.append("implementation_guidance = %s")
            params.append(updates["implementation_guidance"])

        if "severity" in updates:
            set_parts.append("severity = %s")
            params.append(updates["severity"])

        if "description_candidate" in updates:
            # Only update if current is empty/short
            if not ctrl_desc or len(ctrl_desc) < len(updates["description_candidate"]):
                set_parts.append("control_description = %s")
                params.append(updates["description_candidate"])

        if "control_data_merge" in updates:
            # Merge new keys into existing control_data JSONB
            merged = {**ctrl_data, **updates["control_data_merge"]}
            set_parts.append("control_data = %s")
            params.append(json.dumps(merged))

        if not set_parts:
            continue

        set_parts.append("updated_at = NOW()")
        params.append(ctrl_id)

        sql = f"UPDATE compliance_controls SET {', '.join(set_parts)} WHERE control_id = %s"

        if dry_run:
            updated += 1
        else:
            with conn.cursor() as cur:
                cur.execute(sql, params)
            updated += 1

    return matched, updated


def main():
    parser = argparse.ArgumentParser(description="Enrich compliance controls from JSON files")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be updated without writing")
    parser.add_argument("--framework", type=str, help="Only enrich this framework_id")
    parser.add_argument("--verify", action="store_true", help="Show before/after counts")
    args = parser.parse_args()

    import psycopg2
    from psycopg2.extras import Json

    conn_str = (
        f"host={os.environ.get('COMPLIANCE_DB_HOST', 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com')} "
        f"port={os.environ.get('COMPLIANCE_DB_PORT', '5432')} "
        f"dbname={os.environ.get('COMPLIANCE_DB_NAME', 'threat_engine_compliance')} "
        f"user={os.environ.get('COMPLIANCE_DB_USER', 'postgres')} "
        f"password={os.environ.get('COMPLIANCE_DB_PASSWORD', 'jtv2BkJF8qoFtAKP')}"
    )
    conn = psycopg2.connect(conn_str)

    # Framework → (loader_fn, builder_fn)
    HANDLERS = {
        "cis_aws": (load_cis_json, build_cis_update),
        "nist_800_53_rev5": (load_nist_json, build_nist_update),
        "pci_dss_v4": (load_pci_json, build_pci_update),
    }

    if args.verify:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT framework_id,
                       count(*) as total,
                       count(*) FILTER (WHERE implementation_guidance IS NOT NULL AND implementation_guidance != '') as has_guidance,
                       count(*) FILTER (WHERE testing_procedures IS NOT NULL AND testing_procedures != '') as has_testing,
                       count(*) FILTER (WHERE severity IS NOT NULL AND severity != '') as has_severity
                FROM compliance_controls
                WHERE framework_id IN ('cis_aws', 'nist_800_53_rev5', 'pci_dss_v4')
                GROUP BY framework_id ORDER BY framework_id
            """)
            print("\n=== CURRENT STATE ===")
            print(f"{'Framework':<22} {'Total':>6} {'Guidance':>9} {'Testing':>9} {'Severity':>9}")
            print("-" * 60)
            for row in cur.fetchall():
                print(f"{row[0]:<22} {row[1]:>6} {row[2]:>9} {row[3]:>9} {row[4]:>9}")
        print()

    frameworks_to_process = FRAMEWORK_JSON_MAP.keys()
    if args.framework:
        frameworks_to_process = [args.framework]

    total_matched = 0
    total_updated = 0

    for fw_id in frameworks_to_process:
        if fw_id not in FRAMEWORK_JSON_MAP:
            print(f"No JSON mapping for {fw_id}, skipping")
            continue
        if fw_id not in HANDLERS:
            print(f"No handler for {fw_id}, skipping")
            continue

        loader_fn, builder_fn = HANDLERS[fw_id]
        json_files = FRAMEWORK_JSON_MAP[fw_id]

        print(f"\n{'='*60}")
        print(f"Enriching: {fw_id}")
        print(f"{'='*60}")

        matched, updated = enrich_framework(
            conn, fw_id, json_files, loader_fn, builder_fn, args.dry_run
        )
        print(f"  Matched: {matched}, Updated: {updated}")
        total_matched += matched
        total_updated += updated

    if not args.dry_run:
        conn.commit()
        print(f"\n{'='*60}")
        print(f"COMMITTED: {total_updated} controls enriched across {len(list(frameworks_to_process))} frameworks")
    else:
        print(f"\n{'='*60}")
        print(f"DRY RUN: Would update {total_updated} controls (no changes made)")

    # Verify after
    if not args.dry_run:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT framework_id,
                       count(*) as total,
                       count(*) FILTER (WHERE implementation_guidance IS NOT NULL AND implementation_guidance != '') as has_guidance,
                       count(*) FILTER (WHERE testing_procedures IS NOT NULL AND testing_procedures != '') as has_testing,
                       count(*) FILTER (WHERE severity IS NOT NULL AND severity != '') as has_severity
                FROM compliance_controls
                WHERE framework_id IN ('cis_aws', 'nist_800_53_rev5', 'pci_dss_v4')
                GROUP BY framework_id ORDER BY framework_id
            """)
            print(f"\n=== AFTER ENRICHMENT ===")
            print(f"{'Framework':<22} {'Total':>6} {'Guidance':>9} {'Testing':>9} {'Severity':>9}")
            print("-" * 60)
            for row in cur.fetchall():
                print(f"{row[0]:<22} {row[1]:>6} {row[2]:>9} {row[3]:>9} {row[4]:>9}")

    conn.close()


if __name__ == "__main__":
    main()
