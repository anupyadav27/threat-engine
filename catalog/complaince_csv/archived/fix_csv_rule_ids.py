#!/usr/bin/env python3
"""
fix_csv_rule_ids.py
====================
Updates final_compliance_rules_mapped.csv so that all rule_ids in the
check/ciem_check columns match canonical catalog rule_ids.

Strategy per rule_id token (in priority order):
  1. Exact match in column's CSP catalog
  2. Cross-CSP lookup (rule_id prefix → correct CSP catalog)
  3. Suffix normalization: try appending common catalog suffixes
     (_configured, _enforced, _enabled, _check, _disabled, _restricted)
  4. If still unmatched → keep original (logged to missing report)
     NOTE: Do NOT drop — these need new catalog entries created separately.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT    = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "rule"
CSV_IN  = Path(__file__).parent / "final_compliance_rules_mapped.csv"
CSV_OUT = Path(__file__).parent / "final_compliance_rules_mapped.csv"
MISSING_REPORT = Path(__file__).parent / "missing_catalog_rules.txt"

RULE_COLS = [
    "aws_checks", "aws_ciem_checks",
    "azure_checks", "azure_ciem_checks",
    "gcp_checks", "gcp_ciem_checks",
    "oracle_checks", "oracle_ciem_checks",
    "ibm_checks", "ibm_ciem_checks",
    "alicloud_checks", "alicloud_ciem_checks",
    "k8s_checks", "k8s_ciem_checks",
]

COL_CSP = {
    "aws_checks": "aws",       "aws_ciem_checks": "aws",
    "azure_checks": "azure",   "azure_ciem_checks": "azure",
    "gcp_checks": "gcp",       "gcp_ciem_checks": "gcp",
    "oracle_checks": "oci",    "oracle_ciem_checks": "oci",
    "ibm_checks": "ibm",       "ibm_ciem_checks": "ibm",
    "alicloud_checks": "alicloud", "alicloud_ciem_checks": "alicloud",
    "k8s_checks": "k8s",       "k8s_ciem_checks": "k8s",
}

PREFIX_CSP = {
    "aws": "aws", "azure": "azure", "gcp": "gcp",
    "oci": "oci", "ibm": "ibm", "alicloud": "alicloud", "k8s": "k8s",
}

SUFFIXES = [
    "_configured",
    "_enforced",
    "_enabled",
    "_check",
    "_disabled",
    "_restricted",
    "_enabled_and_configured",
    "_enforced_check",
    "_enabled_check",
    "_configured_check",
    "_enabled_enforced",
    "_configured_enforced",
]


def load_catalog() -> Dict[str, Set[str]]:
    catalog: Dict[str, Set[str]] = {}
    for csp in ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]:
        meta_dir = CATALOG / f"{csp}_rule_metadata"
        catalog[csp] = {f.stem for f in meta_dir.rglob("*.yaml")} if meta_dir.exists() else set()
    return catalog


def resolve_rule_id(rid: str, col: str, catalog: Dict[str, Set[str]]) -> Tuple[str, str]:
    """
    Returns (canonical_rule_id, method) where method is one of:
      'exact', 'cross_csp', 'suffix', 'unmatched'
    """
    col_csp = COL_CSP.get(col, "")
    col_catalog = catalog.get(col_csp, set())

    # 1. Exact match in column CSP
    if rid in col_catalog:
        return rid, "exact"

    # 2. Cross-CSP: derive CSP from rule_id prefix
    prefix = rid.split(".")[0].lower() if "." in rid else ""
    rule_csp = PREFIX_CSP.get(prefix, "")
    if rule_csp and rule_csp != col_csp:
        rule_catalog = catalog.get(rule_csp, set())
        if rid in rule_catalog:
            return rid, "cross_csp"

    # Determine which CSP catalog to use for suffix search
    search_csp = rule_csp if rule_csp else col_csp
    search_catalog = catalog.get(search_csp, set())

    # 3. Suffix normalization
    for suffix in SUFFIXES:
        candidate = rid + suffix
        if candidate in search_catalog:
            return candidate, "suffix"

    # 4. Unmatched — keep original so nothing is lost
    return rid, "unmatched"


def resolve_cell(cell: str, col: str, catalog: Dict[str, Set[str]],
                 stats: Dict) -> str:
    if not cell or not cell.strip():
        return cell

    raw = cell.replace(";", "+")
    tokens = [t.strip() for t in raw.split("+") if t.strip()]

    resolved: List[str] = []
    seen: set = set()  # deduplicate within cell
    for rid in tokens:
        canon, method = resolve_rule_id(rid, col, catalog)
        stats[method] += 1
        if method == "suffix":
            stats["suffix_pairs"].append((rid, canon))
        elif method == "unmatched":
            stats["unmatched_ids"].append((col, rid))
        if canon not in seen:
            resolved.append(canon)
            seen.add(canon)

    return "+".join(resolved)


def main():
    print("Loading catalog...")
    catalog = load_catalog()
    for csp, rules in catalog.items():
        print(f"  {csp}: {len(rules)} canonical rule_ids")

    stats: Dict = {
        "exact": 0, "cross_csp": 0, "suffix": 0, "unmatched": 0,
        "suffix_pairs": [], "unmatched_ids": [],
    }

    print(f"\nReading {CSV_IN} ...")
    with open(CSV_IN, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    print(f"Read {len(rows)} rows. Processing...")

    updated_rows = []
    for row in rows:
        new_row = dict(row)
        for col in RULE_COLS:
            new_row[col] = resolve_cell(row.get(col, ""), col, catalog, stats)
        updated_rows.append(new_row)

    total = stats["exact"] + stats["cross_csp"] + stats["suffix"] + stats["unmatched"]
    print(f"\nResults ({total} total rule_id tokens):")
    print(f"  Exact match:      {stats['exact']:5d}")
    print(f"  Cross-CSP match:  {stats['cross_csp']:5d}")
    print(f"  Suffix match:     {stats['suffix']:5d}")
    print(f"  Unmatched:        {stats['unmatched']:5d}  ← need new catalog entries")

    if stats["suffix_pairs"][:15]:
        print(f"\nSuffix renames (first 15):")
        for old, new in stats["suffix_pairs"][:15]:
            print(f"  {old!r:55s} → {new!r}")

    # Write missing rules report
    unmatched_counts = Counter(rid for _, rid in stats["unmatched_ids"])
    with open(MISSING_REPORT, "w") as f:
        f.write(f"# Missing catalog rules ({len(unmatched_counts)} unique rule_ids)\n")
        f.write("# These rule_ids appear in compliance CSV but have no catalog YAML.\n")
        f.write("# New catalog entries need to be created for these.\n\n")
        for rid, cnt in unmatched_counts.most_common():
            # figure out which CSP
            prefix = rid.split(".")[0].lower()
            f.write(f"{rid}  (CSP={prefix}, refs={cnt})\n")
    print(f"\nMissing rules report: {MISSING_REPORT}")
    print(f"  {len(unmatched_counts)} unique rule_ids need new catalog entries")

    print(f"\nWriting {CSV_OUT} ...")
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    print("Done.")


if __name__ == "__main__":
    main()
