#!/usr/bin/env python3
"""
Fix missing discovery_ids for GCP, IBM, AliCloud, and K8s CSPs.

Workflow:
  1. Identify all unmapped for_each values from the Feb backup
  2. Load catalog YAMLs for each CSP
  3. Match for_each → catalog discovery_id
  4. Add unmatched discovery_ids to rule_discoveries
  5. Report before/after counts
  6. Re-run the converter for each CSP that had additions

Usage:
    python3 scripts/fix_missing_discoveries.py [--dry-run] [--csp gcp]
"""

import os
import sys
import glob
import json
import re
import yaml
import psycopg2
import argparse
import subprocess
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────────────
CATALOG_DIR = "/Users/apple/Desktop/threat-engine/catalog"
SCRIPTS_DIR = "/Users/apple/Desktop/threat-engine/scripts"
DB_CONFIG = {
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port": 5432,
    "dbname": "threat_engine_check",
    "user": "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

TARGET_CSPS = ["gcp", "ibm", "alicloud", "k8s"]

# ── Import helpers from converter ────────────────────────────────────────────
sys.path.insert(0, SCRIPTS_DIR)
from convert_feb_backup_rules import (
    parse_backup_checks,
    load_discovery_index,
    match_discovery_id,
    normalize,
    normalize_for_each,
)


# ── YAML loading with error tolerance ────────────────────────────────────────
def _extract_discovery_stubs_from_text(content: str) -> list:
    """
    Fallback: extract discovery_id entries from raw YAML text using regex.
    Returns minimal stub entries with just discovery_id (no calls/emit).
    """
    disc_ids = re.findall(r'discovery_id:\s*(.+)', content)
    entries = []
    for did in disc_ids:
        did = did.strip().strip("'\"")
        if did:
            entries.append({
                "discovery_id": did,
                "calls": [{"action": did.split(".")[-1], "save_as": "response",
                            "on_error": "continue"}],
                "emit": {"as": "item", "items_for": "{{ response }}"},
            })
    return entries


def load_yaml_safe(path: str) -> Optional[dict]:
    """Load a YAML file, with fallback line-filtering for malformed files."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except yaml.YAMLError:
        # Try stripping non-comment, non-indented stray lines
        try:
            with open(path) as f:
                lines = f.readlines()
            cleaned = []
            for line in lines:
                # Keep blank lines, commented lines, indented lines, and key: value lines
                stripped = line.rstrip()
                if not stripped:
                    cleaned.append(line)
                elif stripped.startswith('#'):
                    cleaned.append(line)
                elif stripped.startswith(' ') or stripped.startswith('\t'):
                    cleaned.append(line)
                elif ':' in stripped or stripped.startswith('-'):
                    cleaned.append(line)
                # else: skip stray text lines (like the compute.yaml issue)
            try:
                return yaml.safe_load(''.join(cleaned))
            except Exception:
                pass
            # Last resort: extract discovery_ids via regex
            with open(path) as f:
                raw = f.read()
            stubs = _extract_discovery_stubs_from_text(raw)
            if stubs:
                print(f"  INFO: regex-extracted {len(stubs)} discovery_ids from {path}")
                return {"discovery": stubs}
        except Exception as e2:
            print(f"  WARN: cannot parse {path}: {e2}")
        return None
    except Exception as e:
        print(f"  WARN: cannot read {path}: {e}")
        return None


# GCP service name aliases: backup service name → catalog directory name
GCP_SERVICE_ALIASES = {
    "cloudsql":    "sqladmin",
    "gcs":         "storage",
    "gke":         "container",
    "services":    "iam",          # list_service_account_keys → iam
    "multi":       "cloudresourcemanager",
    "workspace":   "admin",
    "filestore":   "file",
    "bigquery":    ["bigquery", "bigqueryconnection"],  # list_bigquery_connections
    "osconfig":    "osconfig",
    "elasticsearch": None,         # no catalog equivalent
    "datastudio":  None,
}


# ── Catalog loading ──────────────────────────────────────────────────────────
def load_catalog(csp: str) -> dict:
    """
    Returns {service: [discovery_entry_dict, ...]} for all catalog YAMLs.

    GCP:       catalog/gcp/{service}/step6_{service}.discovery.yaml
    Others:    catalog/{csp}/{service}/{service}_discovery.yaml
               also try catalog/{csp}/{service}/step6_{service}.discovery.yaml

    The returned dict always uses the BACKUP service name as key, not the
    catalog directory name, so lookups work correctly.
    """
    catalog_base = os.path.join(CATALOG_DIR, csp)
    result = {}  # {service: [disc_entry, ...]}

    if not os.path.isdir(catalog_base):
        print(f"  WARN: no catalog dir for {csp} at {catalog_base}")
        return result

    def _load_service(svc_dir: str, register_as: str):
        """Load catalog YAML for one service directory and register under register_as."""
        svc_path = os.path.join(catalog_base, svc_dir)
        if not os.path.isdir(svc_path):
            return

        # Candidate YAML files in priority order
        candidates = []
        if csp == "gcp":
            candidates = glob.glob(os.path.join(svc_path, "step6_*.yaml"))
        else:
            # Prefer plain {svc}_discovery.yaml, fall back to step6_
            plain = os.path.join(svc_path, f"{svc_dir}_discovery.yaml")
            step6 = os.path.join(svc_path, f"step6_{svc_dir}.discovery.yaml")
            if os.path.exists(plain):
                candidates.append(plain)
            if os.path.exists(step6):
                candidates.append(step6)

        for yaml_path in candidates:
            data = load_yaml_safe(yaml_path)
            if not data or not isinstance(data, dict):
                continue
            discs = data.get("discovery", [])
            if not isinstance(discs, list):
                continue
            entries = [d for d in discs if isinstance(d, dict) and d.get("discovery_id")]
            if entries:
                if register_as not in result:
                    result[register_as] = []
                result[register_as].extend(entries)
            break  # use first valid candidate

    # Load all catalog service directories
    for svc_dir in sorted(os.listdir(catalog_base)):
        if not os.path.isdir(os.path.join(catalog_base, svc_dir)):
            continue
        _load_service(svc_dir, svc_dir)

    # For GCP: also add alias mappings so backup service names resolve
    if csp == "gcp":
        for backup_svc, catalog_svc in GCP_SERVICE_ALIASES.items():
            if not catalog_svc:
                continue
            # catalog_svc can be a string or list of strings
            catalog_svcs = catalog_svc if isinstance(catalog_svc, list) else [catalog_svc]
            for cs in catalog_svcs:
                if cs in result:
                    if backup_svc not in result:
                        result[backup_svc] = []
                    result[backup_svc].extend(result[cs])
                else:
                    _load_service(cs, backup_svc)

    total = sum(len(v) for v in result.values())
    print(f"  Loaded catalog: {len(result)} services, {total} discovery_ids")
    return result


# ── Matching for_each → catalog discovery_id ─────────────────────────────────
def match_fe_to_catalog(for_each: str, csp: str, service: str,
                         catalog: dict) -> Optional[dict]:
    """
    Find a catalog discovery entry matching the given for_each string.

    Strategies (in order):
      1. Fully-qualified match: for_each IS a qualified discovery_id
      2. Exact last-segment match after normalization
      3. Contains match (bidirectional, len > 5)
      4. Strip list/get/describe prefix from both and compare
      5. Single entry for service (fallback)

    Returns the full catalog entry dict, or None.
    """
    # Collect candidates: service first, then all provider entries
    svc_entries = catalog.get(service, [])
    all_entries = [e for entries in catalog.values() for e in entries]

    # ── Strategy 1: for_each IS a qualified discovery_id ──────────────────
    for entry in all_entries:
        if entry["discovery_id"] == for_each:
            return entry

    # ── Normalize for_each ──────────────────────────────────────────────────
    # For AliCloud: "alicloud.cloudfw.deployed_across_all_vpcs" → last part
    if for_each.startswith(f"{csp}."):
        parts = for_each.split(".")
        fe_resource = parts[-1] if len(parts) >= 3 else for_each
        fe_service = parts[1] if len(parts) >= 3 else service
    else:
        fe_resource = for_each
        fe_service = service

    norm_fe = normalize_for_each(fe_resource)
    norm_fe_full = normalize(for_each)

    if not norm_fe:
        return None

    def score_entry(entry: dict, pool_is_service: bool) -> int:
        did = entry["discovery_id"]
        parts = did.split(".")
        last = normalize(parts[-1]) if parts else ""
        second_last = normalize(parts[-2]) if len(parts) >= 2 else ""
        full = normalize(did)

        # Helper: normalized plural-insensitive comparison
        second_last_ns = second_last.rstrip("s")  # strip trailing 's' for plural
        norm_fe_ns = norm_fe.rstrip("s")           # same for norm_fe

        # Exact last-segment match
        if norm_fe == last or norm_fe_ns == last.rstrip("s"):
            return 10 if pool_is_service else 8
        # Match against second-to-last segment (resource name) — exact or plural-stripped
        if len(norm_fe) > 4 and (norm_fe == second_last or norm_fe_ns == second_last_ns):
            return 7 if pool_is_service else 5
        # norm_fe contained in second_last (GCP camelCase: batchPredictionJobs → batchpredictionjobs)
        if len(norm_fe) > 5 and norm_fe in second_last:
            return 6 if pool_is_service else 4
        # second_last contained in norm_fe (plural-stripped both sides)
        # Use > 3 threshold to catch short resource names like "disk", "key", "sink"
        if len(norm_fe_ns) > 5 and second_last_ns in norm_fe_ns and len(second_last_ns) > 3:
            return 6 if pool_is_service else 4
        # second_last (raw) contained in norm_fe
        if len(norm_fe) > 5 and second_last in norm_fe and len(second_last) > 3:
            return 6 if pool_is_service else 4
        # Last segment contains norm_fe
        if len(norm_fe) > 5 and norm_fe in last:
            return 6 if pool_is_service else 4
        # norm_fe contains last segment
        if len(norm_fe) > 5 and last in norm_fe and len(last) > 5:
            return 5 if pool_is_service else 3
        # Full qualified match
        if len(norm_fe_full) > 5 and norm_fe_full in full:
            return 4 if pool_is_service else 2
        # strip describe/list/get prefix from both last and second_last segments
        stripped_last = re.sub(r'^(list|get|describe|query|aggregated)', '', last)
        stripped_second = re.sub(r'^(list|get|describe|query)', '', second_last)
        # Also strip IBM/GCP "private_cloud_" prefix patterns from norm_fe
        # e.g. "privatecloudserver" → "server", "privatecloudsshkey" → "sshkey"
        stripped_fe = re.sub(r'^(list|get|describe|query|privatecloud)', '', norm_fe)
        stripped_last_ns = stripped_last.rstrip("s")
        stripped_second_ns = stripped_second.rstrip("s")
        stripped_fe_ns = stripped_fe.rstrip("s")
        if stripped_fe_ns and (
            (stripped_last_ns and (
                stripped_fe_ns == stripped_last_ns or
                (len(stripped_fe_ns) > 3 and stripped_fe_ns in stripped_last_ns) or
                (len(stripped_last_ns) > 3 and stripped_last_ns in stripped_fe_ns)
            )) or
            (stripped_second_ns and (
                stripped_fe_ns == stripped_second_ns or
                (len(stripped_fe_ns) > 3 and stripped_fe_ns in stripped_second_ns) or
                (len(stripped_second_ns) > 3 and stripped_second_ns in stripped_fe_ns)
            ))
        ):
            return 5 if pool_is_service else 2
        return 0

    # Search service-specific entries first
    best_entry, best_score = None, 0
    for entry in svc_entries:
        s = score_entry(entry, pool_is_service=True)
        if s > best_score:
            best_entry, best_score = entry, s

    # Good same-service match: use it
    if best_score >= 6:
        return best_entry

    # Looser same-service match for short resource names
    if best_score >= 4 and svc_entries:
        return best_entry

    # Cross-service search — only use if the discovery_id's service segment
    # matches the for_each service name (avoid false positives like bigquery→sqladmin)
    norm_svc = normalize(service)
    norm_fe_svc = normalize(fe_service)
    cross_entries = [
        e for e in all_entries
        if normalize(e["discovery_id"].split(".")[1] if len(e["discovery_id"].split(".")) > 1 else "")
        in (norm_svc, norm_fe_svc)
    ]
    for entry in cross_entries:
        s = score_entry(entry, pool_is_service=False)
        if s > best_score:
            best_entry, best_score = entry, s

    if best_score >= 6:
        return best_entry

    # ── Strategy 5: single entry for service ──────────────────────────────
    if len(svc_entries) == 1:
        return svc_entries[0]

    return None


# ── Build stub discovery entry for virtual/control-plane services ─────────
def build_stub_entry(for_each: str, csp: str, service: str) -> dict:
    """
    Build a minimal stub discovery entry for K8s control-plane or
    virtual resources that have no real API discovery.
    """
    # Derive a canonical discovery_id
    if for_each.startswith(f"{csp}."):
        disc_id = for_each
    else:
        # e.g. list_cluster_resources → k8s.cluster.list
        action = re.sub(r'^(list|get)_', '', for_each)
        action = re.sub(r'_resources?$', '', action)
        disc_id = f"{csp}.{service}.{action}"

    return {
        "discovery_id": disc_id,
        "calls": [
            {
                "action": re.sub(r'^(list|get)_', '', for_each),
                "save_as": "response",
                "on_error": "continue",
            }
        ],
        "emit": {
            "as": "item",
            "items_for": "{{ response }}",
        },
    }


# ── Collect unmapped for_each ─────────────────────────────────────────────
def collect_unmapped(csp: str, disc_index: dict) -> list:
    """
    Returns list of {service, for_each, check_count} for all unmapped checks.
    """
    checks = parse_backup_checks(csp)
    seen = {}
    for c in checks:
        qid = match_discovery_id(c["for_each"], csp, c["service"], disc_index)
        if qid:
            continue
        key = (c["service"], c["for_each"])
        if key not in seen:
            seen[key] = 0
        seen[key] += 1

    return [
        {"service": svc, "for_each": fe, "check_count": cnt}
        for (svc, fe), cnt in sorted(seen.items())
    ]


# ── DB operations ─────────────────────────────────────────────────────────
def check_disc_exists_in_db(conn, service: str, provider: str,
                             disc_id: str) -> bool:
    """Return True if disc_id already exists in rule_discoveries for (service, provider)."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM rule_discoveries,
               jsonb_array_elements(discoveries_data->'discovery') disc
        WHERE service=%s AND provider=%s AND customer_id IS NULL
          AND disc->>'discovery_id' = %s
        LIMIT 1
        """,
        (service, provider, disc_id),
    )
    exists = cur.fetchone() is not None
    cur.close()
    return exists


def row_exists_for_service(conn, service: str, provider: str) -> bool:
    """Return True if there's a rule_discoveries row for (service, provider)."""
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM rule_discoveries WHERE service=%s AND provider=%s "
        "AND customer_id IS NULL LIMIT 1",
        (service, provider),
    )
    exists = cur.fetchone() is not None
    cur.close()
    return exists


def append_discovery_to_db(conn, service: str, provider: str,
                            disc_entry: dict, dry_run: bool) -> bool:
    """
    Append a discovery entry to an existing rule_discoveries row.
    Returns True if successfully appended (or would be in dry-run).
    """
    disc_id = disc_entry["discovery_id"]

    # Check for duplicate
    if not dry_run and check_disc_exists_in_db(conn, service, provider, disc_id):
        print(f"    [SKIP] Already exists: {disc_id}")
        return False

    if dry_run:
        print(f"    [DRY-APPEND] {service}/{provider}: {disc_id}")
        return True

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE rule_discoveries
        SET discoveries_data = jsonb_set(
            discoveries_data,
            '{discovery}',
            (COALESCE(discoveries_data->'discovery', '[]'::jsonb)) || %s::jsonb
        ),
        updated_at = NOW()
        WHERE service=%s AND provider=%s AND customer_id IS NULL
        """,
        (json.dumps([disc_entry]), service, provider),
    )
    conn.commit()
    cur.close()
    print(f"    [APPENDED] {service}/{provider}: {disc_id}")
    return True


def insert_new_row(conn, service: str, provider: str,
                   disc_entry: dict, is_active: bool,
                   dry_run: bool) -> bool:
    """
    Insert a new rule_discoveries row with the given discovery entry.
    Returns True on success.
    """
    disc_id = disc_entry["discovery_id"]

    if dry_run:
        active_str = "ACTIVE" if is_active else "STUB"
        print(f"    [DRY-INSERT] {service}/{provider} [{active_str}]: {disc_id}")
        return True

    discoveries_data = {"discovery": [disc_entry]}
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rule_discoveries
            (service, provider, version, discoveries_data, customer_id, tenant_id,
             source, generated_by, is_active, created_at, updated_at)
        VALUES
            (%s, %s, '1.0', %s::jsonb, NULL, NULL,
             'default', 'fix_missing_discoveries', %s, NOW(), NOW())
        ON CONFLICT DO NOTHING
        """,
        (service, provider, json.dumps(discoveries_data), is_active),
    )
    conn.commit()
    cur.close()
    active_str = "ACTIVE" if is_active else "STUB"
    print(f"    [INSERTED] {service}/{provider} [{active_str}]: {disc_id}")
    return True


# ── Main fix logic per CSP ────────────────────────────────────────────────
def fix_csp(csp: str, conn, dry_run: bool) -> dict:
    """
    Fix missing discoveries for one CSP.
    Returns stats dict.
    """
    print(f"\n{'='*65}")
    print(f"  CSP: {csp.upper()}")
    print(f"{'='*65}")

    # Build fresh disc_index from DB
    disc_index = load_discovery_index(conn)

    # Step 1: Collect unmapped
    unmapped = collect_unmapped(csp, disc_index)
    print(f"\n  Step 1: {len(unmapped)} unmapped (service, for_each) pairs")

    if not unmapped:
        print("  Nothing to fix.")
        return {"unmapped_before": 0, "unmapped_after": 0, "added": 0}

    # Step 2: Load catalog
    print(f"\n  Step 2: Loading catalog for {csp}")
    catalog = load_catalog(csp)

    # Step 3+4: Match and add
    print(f"\n  Step 3+4: Matching and adding discovery_ids")
    stats = {"unmapped_before": len(unmapped), "added": 0, "stubbed": 0,
             "no_match": 0}

    # K8s virtual services that have no real API
    K8S_VIRTUAL_SERVICES = {
        "admission", "apiserver", "audit", "certificate", "cluster",
        "controlplane", "disaster_recovery", "etcd", "event", "federation",
        "general", "horizontalpodautoscaler", "image", "inventory",
        "kubelet", "monitoring", "node", "pod_security", "policy",
        "resource", "scheduler", "software", "workload",
    }

    for item in unmapped:
        service = item["service"]
        for_each = item["for_each"]
        check_count = item["check_count"]

        print(f"\n  [{csp}] {service}: {for_each}  ({check_count} checks)")

        # Determine if this is a virtual/stub service
        is_virtual = False
        if csp == "k8s" and service in K8S_VIRTUAL_SERVICES:
            is_virtual = True
        # AliCloud "virtual" resources (old-format fully-qualified IDs not in catalog)
        if csp == "alicloud" and for_each.startswith("alicloud."):
            is_virtual = True  # treat as needing stub

        # Try catalog match
        catalog_entry = match_fe_to_catalog(for_each, csp, service, catalog)

        if catalog_entry:
            disc_id = catalog_entry["discovery_id"]
            print(f"    → Catalog match: {disc_id}")

            # Decide active state: real catalog entry = active
            is_active = True

            if row_exists_for_service(conn, service, csp):
                if not dry_run and check_disc_exists_in_db(conn, service, csp, disc_id):
                    print(f"    [SKIP] {disc_id} already in DB")
                    continue
                ok = append_discovery_to_db(conn, service, csp, catalog_entry, dry_run)
            else:
                ok = insert_new_row(conn, service, csp, catalog_entry, is_active, dry_run)

            if ok:
                stats["added"] += 1

        elif is_virtual:
            # Build a stub entry for virtual/control-plane services
            stub = build_stub_entry(for_each, csp, service)
            disc_id = stub["discovery_id"]
            print(f"    → Stub (virtual service): {disc_id}")

            if row_exists_for_service(conn, service, csp):
                if not dry_run and check_disc_exists_in_db(conn, service, csp, disc_id):
                    print(f"    [SKIP] {disc_id} already in DB")
                    continue
                ok = append_discovery_to_db(conn, service, csp, stub, dry_run)
            else:
                ok = insert_new_row(conn, service, csp, stub,
                                    is_active=False, dry_run=dry_run)

            if ok:
                stats["stubbed"] += 1

        else:
            print(f"    → NO MATCH in catalog, skipping")
            stats["no_match"] += 1

    # Activate service rows so the converter's load_discovery_index can find them.
    # This covers:
    #  - K8s/AliCloud virtual stubs (was_active=False, now need to be active)
    #  - GCP/IBM rows that existed but were inactive and now have new discovery_ids
    if not dry_run and (stats["added"] > 0 or stats["stubbed"] > 0):
        cur = conn.cursor()
        if csp == "k8s":
            cur.execute(
                """
                UPDATE rule_discoveries
                SET is_active = true, updated_at = NOW()
                WHERE provider = 'k8s'
                  AND customer_id IS NULL
                  AND is_active = false
                  AND service = ANY(%s)
                """,
                (list(K8S_VIRTUAL_SERVICES),),
            )
            print(f"\n  Activated {cur.rowcount} K8s virtual service rows")
        elif csp == "alicloud":
            cur.execute(
                """
                UPDATE rule_discoveries
                SET is_active = true, updated_at = NOW()
                WHERE provider = 'alicloud'
                  AND customer_id IS NULL
                  AND is_active = false
                  AND EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(discoveries_data->'discovery') disc
                    WHERE disc->>'discovery_id' LIKE 'alicloud.%'
                  )
                """,
            )
            print(f"\n  Activated {cur.rowcount} AliCloud virtual service rows")
        elif csp in ("gcp", "ibm"):
            # Activate any existing inactive rows for services that have backup checks
            # (they now have new discovery_ids appended)
            all_backup_svcs = list({c["service"] for c in parse_backup_checks(csp)})
            cur.execute(
                """
                UPDATE rule_discoveries
                SET is_active = true, updated_at = NOW()
                WHERE provider = %s
                  AND customer_id IS NULL
                  AND is_active = false
                  AND service = ANY(%s)
                  AND jsonb_array_length(COALESCE(discoveries_data->'discovery', '[]'::jsonb)) > 0
                """,
                (csp, all_backup_svcs),
            )
            print(f"\n  Activated {cur.rowcount} {csp.upper()} service rows")
        conn.commit()
        cur.close()

    # Step 5: Re-measure unmapped after
    if not dry_run:
        disc_index_after = load_discovery_index(conn)
        unmapped_after = collect_unmapped(csp, disc_index_after)
        stats["unmapped_after"] = len(unmapped_after)
    else:
        # Estimate: assume stubs + catalog additions all resolve
        stats["unmapped_after"] = max(
            0,
            stats["unmapped_before"] - stats["added"] - stats["stubbed"]
        )

    return stats


# ── Report ────────────────────────────────────────────────────────────────
def print_report(csp_stats: dict):
    print(f"\n{'='*65}")
    print("  SUMMARY REPORT")
    print(f"{'='*65}")
    total_before = total_after = total_added = total_stubbed = total_no_match = 0
    for csp, s in csp_stats.items():
        before = s.get("unmapped_before", 0)
        after = s.get("unmapped_after", before)
        added = s.get("added", 0)
        stubbed = s.get("stubbed", 0)
        no_match = s.get("no_match", 0)
        print(f"  {csp.upper():<10} before={before:<4} after={after:<4} "
              f"catalog_added={added:<4} stubs={stubbed:<4} no_match={no_match}")
        total_before += before
        total_after += after
        total_added += added
        total_stubbed += stubbed
        total_no_match += no_match
    print(f"  {'TOTAL':<10} before={total_before:<4} after={total_after:<4} "
          f"catalog_added={total_added:<4} stubs={total_stubbed:<4} no_match={total_no_match}")


# ── Re-run converter ──────────────────────────────────────────────────────
def rerun_converter(csps: list, dry_run: bool):
    if dry_run:
        print(f"\n  [DRY] Would re-run converter for: {', '.join(csps)}")
        return
    converter = os.path.join(SCRIPTS_DIR, "convert_feb_backup_rules.py")
    for csp in csps:
        print(f"\n  Re-running converter for {csp}...")
        result = subprocess.run(
            ["python3", converter, "--csp", csp],
            capture_output=False,  # stream output
        )
        if result.returncode != 0:
            print(f"  WARN: converter exited with code {result.returncode} for {csp}")
        else:
            print(f"  Converter completed for {csp}")


# ── Entry point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Fix missing discovery_ids for GCP, IBM, AliCloud, K8s"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without modifying DB")
    parser.add_argument("--csp", default=None,
                        help="Process only this CSP (gcp/ibm/alicloud/k8s)")
    args = parser.parse_args()

    conn = psycopg2.connect(**DB_CONFIG)

    csps = [args.csp] if args.csp else TARGET_CSPS
    if args.csp and args.csp not in TARGET_CSPS:
        print(f"ERROR: {args.csp} not in {TARGET_CSPS}")
        sys.exit(1)

    csp_stats = {}
    csps_with_additions = []

    for csp in csps:
        stats = fix_csp(csp, conn, dry_run=args.dry_run)
        csp_stats[csp] = stats
        if stats.get("added", 0) + stats.get("stubbed", 0) > 0:
            csps_with_additions.append(csp)

    print_report(csp_stats)

    # Re-run converter for CSPs that had new discoveries added
    if csps_with_additions:
        print(f"\n  CSPs with new discoveries: {', '.join(csps_with_additions)}")
        rerun_converter(csps_with_additions, dry_run=args.dry_run)
    else:
        print("\n  No new discoveries added — converter not re-run.")

    conn.close()


if __name__ == "__main__":
    main()
