#!/usr/bin/env python3
"""
Step6 Discovery YAML Quality Audit  (v2 – corrected CSP ID canonicalization)

Checks:
  1. Op coverage: step2 ops vs step6 discovery_ids
  2. Dependency wiring: dependent ops with/without for_each
  3. Field emission completeness: ops with no item: section
  4. Structural correctness: save_as, as:item, items_for misuse
"""

import json
import os
import yaml
from pathlib import Path
from collections import defaultdict

BASE = Path("/Users/apple/Desktop/threat-engine/data_pythonsdk")
CSPS = ["aws", "gcp", "azure", "oci", "ibm", "alicloud"]

# ─── helpers ────────────────────────────────────────────────────────────────

def find_step6_yaml(svc_dir: Path) -> Path | None:
    for f in svc_dir.iterdir():
        name = f.name
        if f.suffix == ".yaml" and "backup" not in name:
            if name.startswith("step6_") or "discovery" in name:
                return f
    return None


def load_step6(path: Path) -> list:
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data.get("discovery", []) or []
        return []
    except Exception:
        return []


def find_step2_read(svc_dir: Path) -> Path | None:
    for f in svc_dir.iterdir():
        if f.name == "step2_read_operation_registry.json":
            return f
    return None


def load_step2_ops(path: Path, csp: str) -> dict:
    """
    Returns dict: canonical_id -> {independent, kind}
    Canonical IDs match what step6 uses for discovery_id.
    """
    try:
        with open(path) as fh:
            data = json.load(fh)
    except Exception:
        return {}

    ops_raw = data.get("operations", {})
    result = {}
    svc = data.get("service", "")

    if csp == "aws":
        # step6 uses: aws.{service}.{yaml_action}
        for op_name, op_data in ops_raw.items():
            yaml_action = op_data.get("yaml_action", op_name.lower())
            canonical = f"aws.{svc}.{yaml_action}"
            result[canonical] = {
                "independent": op_data.get("independent", True),
                "kind": op_data.get("kind", ""),
            }

    elif csp == "gcp":
        # step6 uses: gcp.{service}.{resource}.{method}  (full-id keys in step2)
        for op_id, op_data in ops_raw.items():
            result[op_id] = {
                "independent": op_data.get("independent", True),
                "kind": op_data.get("kind", ""),
            }

    elif csp == "azure":
        # step6 uses: azure.{service}.{op_key}  (op_key == yaml_action)
        for op_name, op_data in ops_raw.items():
            canonical = f"azure.{svc}.{op_name}"
            result[canonical] = {
                "independent": op_data.get("independent", True),
                "kind": op_data.get("kind", ""),
            }

    elif csp == "oci":
        # step6 uses: oci.{service}.{op_name}
        for op_name, op_data in ops_raw.items():
            canonical = f"oci.{svc}.{op_name}"
            result[canonical] = {
                "independent": op_data.get("independent", True),
                "kind": op_data.get("kind", ""),
            }

    elif csp == "ibm":
        # step6 uses: ibm.{service}.{yaml_action}  (yaml_action uses dashes)
        for op_name, op_data in ops_raw.items():
            yaml_action = op_data.get("yaml_action", op_name)
            canonical = f"ibm.{svc}.{yaml_action}"
            result[canonical] = {
                "independent": op_data.get("independent", True),
                "kind": op_data.get("kind", ""),
            }

    return result


def load_alicloud_ops(svc_dir: Path, svc: str) -> dict:
    """
    Load alicloud ops from alicloud_dependencies_with_python_names_fully_enriched.json.
    step6 uses: alicloud.{service}.{python_method}
    """
    dep_path = svc_dir / "alicloud_dependencies_with_python_names_fully_enriched.json"
    if not dep_path.exists():
        return {}
    try:
        with open(dep_path) as fh:
            data = json.load(fh)
    except Exception:
        return {}

    svc_data = data.get(svc, {})
    result = {}
    for op in svc_data.get("independent", []):
        pm = op.get("python_method", "")
        canonical = f"alicloud.{svc}.{pm}"
        result[canonical] = {"independent": True, "kind": "read_list"}
    for op in svc_data.get("dependent", []):
        pm = op.get("python_method", "")
        canonical = f"alicloud.{svc}.{pm}"
        result[canonical] = {"independent": False, "kind": "read_get"}
    return result


def has_for_each(disc_entry: dict) -> bool:
    for call in disc_entry.get("calls", []):
        if "for_each" in call:
            return True
    return "for_each" in str(disc_entry)


def has_item_section(disc_entry: dict) -> bool:
    emit = disc_entry.get("emit", {})
    if not emit:
        return False
    return "item" in emit and emit["item"] is not None


def has_items_for(disc_entry: dict) -> bool:
    emit = disc_entry.get("emit", {})
    return bool(emit.get("items_for"))


def has_save_as_response(disc_entry: dict) -> bool:
    return any(c.get("save_as") == "response" for c in disc_entry.get("calls", []))


def has_as_item(disc_entry: dict) -> bool:
    return disc_entry.get("emit", {}).get("as") == "item"


# ─── per-service analysis ───────────────────────────────────────────────────

def analyze_service(csp: str, svc: str, svc_dir: Path) -> dict | None:
    s6_path = find_step6_yaml(svc_dir)
    if s6_path is None:
        return None
    disc_list = load_step6(s6_path)
    if not disc_list:
        return {"svc": svc, "no_step6": True}

    s6_ids = {d.get("discovery_id", "") for d in disc_list if d.get("discovery_id")}

    if csp == "alicloud":
        s2_ops = load_alicloud_ops(svc_dir, svc)
    else:
        s2_path = find_step2_read(svc_dir)
        s2_ops = load_step2_ops(s2_path, csp) if s2_path else {}

    s2_ids = set(s2_ops.keys())

    # Check 1: Coverage
    missing_in_s6 = s2_ids - s6_ids
    extra_in_s6   = s6_ids - s2_ids

    # Check 2: Dependency wiring
    dep_with_foreach    = 0
    dep_without_foreach = 0
    for d in disc_list:
        did = d.get("discovery_id", "")
        s2_info = s2_ops.get(did, {})
        if s2_info and not s2_info.get("independent", True):
            if has_for_each(d):
                dep_with_foreach += 1
            else:
                dep_without_foreach += 1

    # Check 3: Field emission completeness
    no_item_section = sum(1 for d in disc_list if not has_item_section(d))

    # Check 4: Structural correctness
    missing_save_as         = 0
    missing_as_item         = 0
    list_without_items_for  = 0
    get_with_items_for      = 0
    for d in disc_list:
        did  = d.get("discovery_id", "")
        kind = s2_ops.get(did, {}).get("kind", "")

        if not has_save_as_response(d):
            missing_save_as += 1
        emit = d.get("emit", {})
        if emit and not has_as_item(d):
            missing_as_item += 1
        if kind == "read_list" and not has_items_for(d):
            list_without_items_for += 1
        if kind in ("read_get", "read_describe") and has_items_for(d):
            get_with_items_for += 1

    return {
        "svc": svc,
        "s6_count": len(disc_list),
        "s2_count": len(s2_ids),
        "missing_in_s6": len(missing_in_s6),
        "extra_in_s6":   len(extra_in_s6),
        "missing_in_s6_examples": sorted(missing_in_s6)[:3],
        "extra_in_s6_examples":   sorted(extra_in_s6)[:3],
        "dep_with_foreach":    dep_with_foreach,
        "dep_without_foreach": dep_without_foreach,
        "no_item_section": no_item_section,
        "missing_save_as":         missing_save_as,
        "missing_as_item":         missing_as_item,
        "list_without_items_for":  list_without_items_for,
        "get_with_items_for":      get_with_items_for,
    }


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("  STEP6 DISCOVERY YAML QUALITY AUDIT  (v2)")
    print("=" * 80)

    global_totals  = defaultdict(int)
    csp_summaries  = {}

    for csp in CSPS:
        csp_dir = BASE / csp
        if not csp_dir.is_dir():
            print(f"\n[SKIP] {csp}: directory not found")
            continue

        services = sorted([d for d in csp_dir.iterdir() if d.is_dir()])
        results  = []
        for svc_dir in services:
            r = analyze_service(csp, svc_dir.name, svc_dir)
            if r:
                results.append(r)

        valid   = [r for r in results if not r.get("no_step6")]
        skipped = len(results) - len(valid)

        totals = defaultdict(int)
        totals["services"] = len(valid)
        totals["skipped"]  = skipped
        for r in valid:
            for key in (
                "s6_count", "s2_count",
                "missing_in_s6", "extra_in_s6",
                "dep_with_foreach", "dep_without_foreach",
                "no_item_section",
                "missing_save_as", "missing_as_item",
                "list_without_items_for", "get_with_items_for",
            ):
                totals[key] += r.get(key, 0)

        csp_summaries[csp] = totals

        # ── Print CSP section ──────────────────────────────────────────────
        print(f"\n{'─'*80}")
        print(f"  CSP: {csp.upper()}  ({len(valid)} services, {skipped} skipped/empty)")
        print(f"{'─'*80}")

        # Check 1
        pct_gap = totals["missing_in_s6"] / max(totals["s2_count"], 1) * 100
        print(f"\n  CHECK 1 – Op Coverage")
        print(f"    Total step2 ops  : {totals['s2_count']:>7}")
        print(f"    Total step6 ops  : {totals['s6_count']:>7}")
        print(f"    Missing in step6 : {totals['missing_in_s6']:>7}  ({pct_gap:.1f}% of step2 not covered)")
        print(f"    Extra in step6   : {totals['extra_in_s6']:>7}  (orphans – no step2 match)")
        worst_cov = sorted(valid, key=lambda r: r["missing_in_s6"], reverse=True)[:5]
        if worst_cov and worst_cov[0]["missing_in_s6"] > 0:
            print(f"    Top-5 services with most missing ops:")
            for r in worst_cov:
                if r["missing_in_s6"] > 0:
                    print(f"      {r['svc']}: {r['missing_in_s6']} missing  e.g. {r['missing_in_s6_examples']}")

        # Check 2
        total_dep = totals["dep_with_foreach"] + totals["dep_without_foreach"]
        print(f"\n  CHECK 2 – Dependency Wiring (for_each)")
        print(f"    Total dependent ops in step6 : {total_dep:>7}")
        print(f"    WITH for_each                : {totals['dep_with_foreach']:>7}")
        print(f"    WITHOUT for_each  [GAP]      : {totals['dep_without_foreach']:>7}")
        svcs_missing = sorted(
            [r for r in valid if r["dep_without_foreach"] > 0],
            key=lambda r: r["dep_without_foreach"], reverse=True
        )[:10]
        if svcs_missing:
            print(f"    Top-10 services missing for_each on dependent ops:")
            for r in svcs_missing:
                print(f"      {r['svc']}: {r['dep_without_foreach']} dependent ops lack for_each")

        # Check 3
        pct_empty = totals["no_item_section"] / max(totals["s6_count"], 1) * 100
        print(f"\n  CHECK 3 – Field Emission Completeness")
        print(f"    Ops with NO item: section    : {totals['no_item_section']:>7}  ({pct_empty:.1f}% of step6 ops emit nothing)")
        worst_emit = sorted(valid, key=lambda r: r["no_item_section"], reverse=True)[:5]
        if worst_emit and worst_emit[0]["no_item_section"] > 0:
            print(f"    Top-5 services by empty emissions:")
            for r in worst_emit:
                if r["no_item_section"] > 0:
                    print(f"      {r['svc']}: {r['no_item_section']} ops emit nothing  ({r['no_item_section']/max(r['s6_count'],1)*100:.0f}% of svc)")

        # Check 4
        print(f"\n  CHECK 4 – Structural Correctness")
        print(f"    Missing save_as: response    : {totals['missing_save_as']:>7}")
        print(f"    Missing as: item  (emit set) : {totals['missing_as_item']:>7}")
        print(f"    read_list WITHOUT items_for  : {totals['list_without_items_for']:>7}")
        print(f"    read_get/describe + items_for: {totals['get_with_items_for']:>7}  (likely incorrect)")

        for key, val in totals.items():
            global_totals[key] += val

    # ── Global summary table ────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("  GLOBAL SUMMARY  (all CSPs combined)")
    print(f"{'='*80}")
    hdr = f"  {'CSP':<12} {'Svcs':>5} {'S2 ops':>8} {'S6 ops':>8} {'Missing%':>9} {'Extra':>7} {'DepNoFE':>8} {'NoItem%':>8} {'NoSave':>7} {'NoAsItm':>8}"
    print(hdr)
    print("  " + "─"*76)
    for csp in CSPS:
        if csp not in csp_summaries:
            continue
        t = csp_summaries[csp]
        pct_miss  = t["missing_in_s6"] / max(t["s2_count"],  1) * 100
        pct_noitm = t["no_item_section"] / max(t["s6_count"], 1) * 100
        print(
            f"  {csp:<12} {t['services']:>5} {t['s2_count']:>8} {t['s6_count']:>8} "
            f"{pct_miss:>8.1f}% {t['extra_in_s6']:>7} "
            f"{t['dep_without_foreach']:>8} {pct_noitm:>7.1f}% "
            f"{t['missing_save_as']:>7} {t['missing_as_item']:>8}"
        )

    # grand total row
    t = global_totals
    pct_miss  = t["missing_in_s6"]  / max(t["s2_count"],  1) * 100
    pct_noitm = t["no_item_section"] / max(t["s6_count"],  1) * 100
    print("  " + "─"*76)
    print(
        f"  {'TOTAL':<12} {t['services']:>5} {t['s2_count']:>8} {t['s6_count']:>8} "
        f"{pct_miss:>8.1f}% {t['extra_in_s6']:>7} "
        f"{t['dep_without_foreach']:>8} {pct_noitm:>7.1f}% "
        f"{t['missing_save_as']:>7} {t['missing_as_item']:>8}"
    )

    print(f"\n  Column definitions:")
    print(f"    Svcs     = valid services (step6 exists and non-empty)")
    print(f"    S2 ops   = total read operations in step2 registry")
    print(f"    S6 ops   = total discovery entries in step6 YAML")
    print(f"    Missing% = % of step2 ops absent from step6 (coverage gap)")
    print(f"    Extra    = step6 entries with no matching step2 op (orphans)")
    print(f"    DepNoFE  = dependent ops in step6 missing for_each wiring")
    print(f"    NoItem%  = % of step6 ops that have no item: emit block")
    print(f"    NoSave   = ops missing save_as: response on any call")
    print(f"    NoAsItm  = emit blocks that exist but are missing as: item")
    print()


if __name__ == "__main__":
    main()
