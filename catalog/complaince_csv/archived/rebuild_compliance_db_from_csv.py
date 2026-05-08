#!/usr/bin/env python3
"""
rebuild_compliance_db_from_csv.py
==================================
Rebuilds compliance_controls, compliance_frameworks, and rule_control_mapping
tables from final_compliance_rules_mapped.csv.

This is the authoritative source of truth for:
  - Which rules map to which compliance controls
  - What frameworks exist
  - What controls each framework contains

Schema preserved; data replaced.

Outputs a JSON payload (for kubectl cp + pod execution).
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

CSV_PATH = Path(__file__).parent / "final_compliance_rules_mapped.csv"
OUT_JSON = Path(__file__).parent / "compliance_rebuild_payload.json"

RULE_COL_TO_CSP = {
    "aws_checks":        "aws",
    "aws_ciem_checks":   "aws",
    "azure_checks":      "azure",
    "azure_ciem_checks": "azure",
    "gcp_checks":        "gcp",
    "gcp_ciem_checks":   "gcp",
    "oracle_checks":     "oci",
    "oracle_ciem_checks":"oci",
    "ibm_checks":        "ibm",
    "ibm_ciem_checks":   "ibm",
    "alicloud_checks":   "alicloud",
    "alicloud_ciem_checks": "alicloud",
    "k8s_checks":        "k8s",
    "k8s_ciem_checks":   "k8s",
}

RULE_COLS = list(RULE_COL_TO_CSP.keys())


def normalize_framework_id(framework_name: str, version: str = "") -> str:
    """Convert framework name to a stable lowercase ID."""
    s = framework_name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    if version:
        v = version.lower().strip()
        v = re.sub(r"[^a-z0-9]+", "_", v).strip("_")
        if v and v not in s:
            s = f"{s}_{v}"
    return s


def get_framework_id(row: dict) -> str:
    """Derive framework_id from CSV row."""
    uid = row.get("unique_compliance_id", "")
    if uid:
        # uid like canada_pbmm_moderate_CCCS_AC_1 → framework part is prefix
        # The framework= column is more reliable
        fw = row.get("framework", "").strip()
        ver = row.get("framework_version", "").strip()
        return normalize_framework_id(fw, ver)
    return "unknown"


def get_provider_from_unique_id(uid: str) -> str:
    """Infer provider from unique_compliance_id prefix."""
    # Multi-cloud frameworks apply to all providers
    return "multi_cloud"


def main():
    print(f"Reading {CSV_PATH} ...")
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"  {len(rows)} rows")

    # ─── 1. Build compliance_frameworks ──────────────────────────────────────
    frameworks: Dict[str, dict] = {}
    for row in rows:
        fw_name = row.get("framework", "").strip()
        fw_ver  = row.get("framework_version", "").strip()
        if not fw_name:
            continue
        fid = normalize_framework_id(fw_name, fw_ver)
        if fid not in frameworks:
            frameworks[fid] = {
                "framework_id":   fid,
                "framework_name": fw_name,
                "version":        fw_ver or None,
                "description":    f"{fw_name} compliance framework",
                "authority":      fw_name.split("_")[0].upper(),
                "category":       "security",
                "is_active":      True,
                "framework_data": {},
            }

    print(f"  {len(frameworks)} unique frameworks")

    # ─── 2. Build compliance_controls ────────────────────────────────────────
    controls: Dict[str, dict] = {}
    for row in rows:
        uid = row.get("unique_compliance_id", "").strip()
        if not uid:
            continue
        fw_name = row.get("framework", "").strip()
        fw_ver  = row.get("framework_version", "").strip()
        fid = normalize_framework_id(fw_name, fw_ver)

        controls[uid] = {
            "control_id":          uid,
            "framework_id":        fid,
            "control_number":      row.get("control_id", "").strip() or uid,
            "control_name":        (row.get("title", "") or "").strip()[:255],
            "control_description": (row.get("description", "") or "").strip(),
            "severity":            (row.get("severity", "") or "medium").strip().lower(),
            "section_name":        (row.get("section", "") or "").strip()[:100] or "General",
            "assessment_type":     (row.get("automation_type", "") or "automated").strip(),
            "is_active":           True,
            "control_data":        {},
        }

    print(f"  {len(controls)} unique controls")

    # ─── 3. Build rule_control_mapping ───────────────────────────────────────
    # (rule_id, control_id, framework_id) → deduplicated
    mappings: List[dict] = []
    seen_pairs: Set[Tuple[str, str]] = set()

    for row in rows:
        uid = row.get("unique_compliance_id", "").strip()
        if not uid:
            continue
        fw_name = row.get("framework", "").strip()
        fw_ver  = row.get("framework_version", "").strip()
        fid = normalize_framework_id(fw_name, fw_ver)

        for col in RULE_COLS:
            cell = row.get(col, "").strip()
            if not cell:
                continue
            for rid in [r.strip() for r in cell.split("+") if r.strip()]:
                pair = (rid, uid)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                mappings.append({
                    "rule_id":    rid,
                    "control_id": uid,
                    "framework_id": fid,
                    "mapping_type": "automated",
                    "is_active": True,
                })

    print(f"  {len(mappings)} rule_control_mapping entries")
    print(f"  {len(set(m['rule_id'] for m in mappings))} unique rule_ids")

    # ─── 4. Write payload ────────────────────────────────────────────────────
    payload = {
        "frameworks": list(frameworks.values()),
        "controls":   list(controls.values()),
        "mappings":   mappings,
    }
    with open(OUT_JSON, "w") as f:
        json.dump(payload, f)

    print(f"\nPayload written: {OUT_JSON}")
    print(f"  Size: {OUT_JSON.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
