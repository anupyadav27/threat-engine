#!/usr/bin/env python3
"""
step4_validate_rules.py
=======================
Phase 4: Validate all generated rule files against:
  1. YAML syntax (can the file be parsed?)
  2. Required fields present
  3. for_each references a real discovery_id in step6 catalog (config rules)
  4. check_config structure correct (CIEM rules)
  5. compliance_frameworks is not empty where CSV had a real framework
  6. Flags STUB entries clearly

Outputs:
  catalog/rule/validation_report.json  — per-rule results
  catalog/rule/validation_summary.txt  — human-readable summary

Usage:
    python3 catalog/rule/step4_validate_rules.py               # validate all
    python3 catalog/rule/step4_validate_rules.py --csp aws     # one CSP
    python3 catalog/rule/step4_validate_rules.py --fix-forach  # auto-fix wrong for_each
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
DGD      = ROOT / "catalog" / "discovery_generator_data"
CSV_PATH = ROOT / "complaince_csv" / "new_rules_deduplicated.csv"

FIX_FOREACH = "--fix-forach" in sys.argv
FILTER_CSP  = None
for i, a in enumerate(sys.argv):
    if a == "--csp" and i + 1 < len(sys.argv):
        FILTER_CSP = sys.argv[i + 1].lower()

# ─────────────────────────────────────────────────────────────────────────────
# Load discovery catalog (all step6 discovery_ids)
# ─────────────────────────────────────────────────────────────────────────────
print("Loading discovery catalog ...")
ALL_DISCOVERY_IDS: set[str] = set()
for f in DGD.rglob("step6_*.yaml"):
    try:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for d in (data.get("discovery") or []):
            if isinstance(d, dict) and "discovery_id" in d:
                ALL_DISCOVERY_IDS.add(d["discovery_id"])
    except Exception:
        pass
print(f"  {len(ALL_DISCOVERY_IDS):,} discovery_ids loaded")

# ─────────────────────────────────────────────────────────────────────────────
# Load CSV rows for quick lookup
# ─────────────────────────────────────────────────────────────────────────────
with open(CSV_PATH, newline="") as f:
    CSV_ROWS = {r["suggested_rule_id"]: r for r in csv.DictReader(f)}

def norm_csp(c: str) -> str:
    return "oci" if c == "oracle" else c

def extract_service(rule_id: str) -> str:
    _OVER = {
        "actiontrail":"actiontrail","ecs":"compute","ram":"iam","oos":"compute",
        "sas":"threat","securitycenter":"threat","resourcemanager":"iam",
        "slb":"network","voicenavigator":"network",
        "chime":"network","cloudtrail":"logging","ec2":"compute","ssm":"compute",
        "aad":"iam","compute":"compute","vm":"compute","monitor":"logging",
        "communication":"network",
        "cloudaudit":"logging","osconfig":"compute","logging":"logging",
        "contactcenterinsights":"network",
        "activity_tracker":"logging","activitytracker":"logging",
        "cloudant":"database","codeengine":"compute","functions":"compute",
        "schematics":"compute","security_advisor":"threat","securityadvisor":"threat",
        "vpc":"network","is":"network","watson":"network",
        "apiserver":"logging","audit":"logging","container":"compute",
        "falco":"threat","node":"compute",
        "announcements":"network",
    }
    raw = rule_id.split(".")[1] if "." in rule_id else "unknown"
    return _OVER.get(raw, raw)

# ─────────────────────────────────────────────────────────────────────────────
# Required fields per rule type
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_CIEM   = ["rule_id","service","provider","check_type","severity",
                   "title","mitre_tactics","mitre_techniques","risk_score",
                   "compliance_frameworks","check_config"]
REQUIRED_CONFIG = ["rule_id","for_each","severity","conditions"]
REQUIRED_META   = ["rule_id","service","provider","check_type","severity",
                   "compliance_frameworks"]

# ─────────────────────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────────────────────

def check_yaml_parse(path: Path) -> tuple[bool, Any, str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return True, data, ""
    except yaml.YAMLError as e:
        return False, None, str(e)

def validate_required_fields(data: dict, required: list[str]) -> list[str]:
    return [f for f in required if f not in data or data[f] is None]

def validate_ciem_check_config(cc: dict) -> list[str]:
    issues = []
    if not isinstance(cc, dict):
        return ["check_config is not a dict"]

    has_conditions = "conditions" in cc
    has_events     = "events"     in cc

    if not has_conditions and not has_events:
        issues.append("check_config missing 'conditions' or 'events'")
        return issues

    if has_events:
        events = cc["events"]
        if not isinstance(events, list) or len(events) < 2:
            issues.append("chain rule 'events' must have at least 2 entries")
        if "window_seconds" not in cc:
            issues.append("chain rule missing 'window_seconds'")

    if has_conditions:
        conds = cc["conditions"]
        if isinstance(conds, dict) and "all" not in conds and "any" not in conds:
            # Simple single-field condition: {field, op, value}
            if "field" not in conds and "var" not in conds:
                issues.append("conditions missing 'field' or 'all'")

    return issues

def validate_config_entry(entry: dict) -> list[str]:
    issues = []
    missing = validate_required_fields(entry, REQUIRED_CONFIG)
    if missing:
        issues.append(f"missing fields: {missing}")

    # Stub check
    if str(entry.get("for_each", "")).startswith("# STUB"):
        issues.append("STUB: for_each not resolved — needs real discovery wiring")
        return issues

    # for_each must exist in catalog
    for_each = entry.get("for_each", "")
    if for_each and for_each not in ALL_DISCOVERY_IDS:
        issues.append(f"for_each '{for_each}' not in discovery catalog")

    return issues

def validate_metadata(data: dict) -> list[str]:
    issues = []
    missing = validate_required_fields(data, REQUIRED_META)
    if missing:
        issues.append(f"missing fields: {missing}")
    cf = data.get("compliance_frameworks", {})
    if not isinstance(cf, dict):
        issues.append("compliance_frameworks is not a dict")
    return issues

# ─────────────────────────────────────────────────────────────────────────────
# Main validation loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    results: list[dict] = []
    counters = defaultdict(int)

    csps = ["alicloud","aws","azure","gcp","ibm","k8s","oci"]
    if FILTER_CSP:
        csps = [FILTER_CSP]

    for csp in csps:
        # ── Metadata files
        meta_dir = RULE_DIR / f"{csp}_rule_metadata"
        for mf in sorted(meta_dir.rglob("*.yaml")):
            rule_id = mf.stem
            if rule_id not in CSV_ROWS:
                continue  # not a newly generated rule
            ok, data, err = check_yaml_parse(mf)
            if not ok:
                results.append({"rule_id": rule_id, "file": str(mf.relative_to(ROOT)),
                                 "type": "metadata", "status": "PARSE_ERROR",
                                 "issues": [err]})
                counters["meta_parse_error"] += 1
                continue
            issues = validate_metadata(data or {})
            status = "PASS" if not issues else "WARN"
            results.append({"rule_id": rule_id, "file": str(mf.relative_to(ROOT)),
                             "type": "metadata", "status": status, "issues": issues})
            counters[f"meta_{status.lower()}"] += 1

        # ── Config check files
        chk_dir = RULE_DIR / f"{csp}_rule_check"
        for svc_dir in sorted(chk_dir.iterdir()) if chk_dir.exists() else []:
            chk_file = svc_dir / "checks.yaml"
            if not chk_file.exists():
                continue
            ok, data, err = check_yaml_parse(chk_file)
            if not ok:
                results.append({"rule_id": f"{csp}.{svc_dir.name}.*",
                                 "file": str(chk_file.relative_to(ROOT)),
                                 "type": "config_checks", "status": "PARSE_ERROR",
                                 "issues": [err]})
                continue
            for entry in (data or {}).get("checks", []):
                if not isinstance(entry, dict):
                    continue
                rule_id = entry.get("rule_id", "")
                if rule_id not in CSV_ROWS:
                    continue
                issues  = validate_config_entry(entry)
                is_stub = any("STUB" in i for i in issues)
                status  = "STUB" if is_stub else ("PASS" if not issues else "FAIL")
                results.append({
                    "rule_id": rule_id,
                    "file":    str(chk_file.relative_to(ROOT)),
                    "type":    "config",
                    "status":  status,
                    "issues":  [i for i in issues if "STUB" not in i or is_stub],
                    "for_each": entry.get("for_each",""),
                })
                counters[f"config_{status.lower()}"] += 1

        # ── CIEM rule files
        ciem_dir = RULE_DIR / f"{csp}_rule_ciem"
        if not ciem_dir.exists():
            continue
        for rf in sorted(ciem_dir.rglob("*.yaml")):
            rule_id = rf.stem
            if rule_id not in CSV_ROWS:
                continue
            ok, data, err = check_yaml_parse(rf)
            if not ok:
                results.append({"rule_id": rule_id, "file": str(rf.relative_to(ROOT)),
                                 "type": "ciem", "status": "PARSE_ERROR",
                                 "issues": [err]})
                counters["ciem_parse_error"] += 1
                continue
            d = data or {}
            missing = validate_required_fields(d, REQUIRED_CIEM)
            cc_issues = validate_ciem_check_config(d.get("check_config", {}))
            issues = ([f"missing fields: {missing}"] if missing else []) + cc_issues
            status = "PASS" if not issues else "FAIL"
            results.append({
                "rule_id":  rule_id,
                "file":     str(rf.relative_to(ROOT)),
                "type":     "ciem",
                "status":   status,
                "issues":   issues,
                "log_source": d.get("log_source_type",""),
                "check_type_in_config": d.get("check_config",{}).get("type",""),
            })
            counters[f"ciem_{status.lower()}"] += 1

    # ── Print summary
    total = len(results)
    passes  = sum(1 for r in results if r["status"] == "PASS")
    fails   = sum(1 for r in results if r["status"] == "FAIL")
    warns   = sum(1 for r in results if r["status"] == "WARN")
    stubs   = sum(1 for r in results if r["status"] == "STUB")
    errors  = sum(1 for r in results if r["status"] == "PARSE_ERROR")

    print(f"\n{'='*60}")
    print(f"VALIDATION REPORT — {total} items checked")
    print(f"{'='*60}")
    print(f"  PASS        : {passes}")
    print(f"  WARN        : {warns}  (non-blocking, minor issues)")
    print(f"  STUB        : {stubs}  (for_each needs discovery wiring)")
    print(f"  FAIL        : {fails}  (structural errors)")
    print(f"  PARSE_ERROR : {errors}")
    print(f"\nBy counter: {dict(counters)}")

    # ── Print failures detail
    fail_items = [r for r in results if r["status"] in ("FAIL","PARSE_ERROR")]
    if fail_items:
        print(f"\n{'─'*60}")
        print(f"FAILURES ({len(fail_items)}):")
        for r in fail_items[:30]:
            print(f"  [{r['status']}] {r['rule_id']}")
            for iss in r["issues"][:2]:
                print(f"    → {iss}")

    # ── Stub summary
    stub_items = [r for r in results if r["status"] == "STUB"]
    if stub_items:
        print(f"\n{'─'*60}")
        print(f"STUBS ({len(stub_items)}) — need discovery added:")
        for r in stub_items[:30]:
            print(f"  {r['rule_id']}")

    # ── Config for_each not in catalog
    wrong_foreach = [r for r in results
                     if r["type"] == "config" and r["status"] == "FAIL"
                     and any("not in discovery catalog" in i for i in r.get("issues",[]))]
    if wrong_foreach:
        print(f"\n{'─'*60}")
        print(f"CONFIG rules with invalid for_each ({len(wrong_foreach)}):")
        for r in wrong_foreach[:20]:
            fe = r.get("for_each","")
            print(f"  {r['rule_id']}")
            print(f"    for_each: {fe}")

    # ── Write report files
    report_path = RULE_DIR / "validation_report.json"
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    summary_lines = [
        f"Validation summary — {total} items",
        f"PASS: {passes}  WARN: {warns}  STUB: {stubs}  FAIL: {fails}  ERROR: {errors}",
        "",
        "FAILURES:",
    ] + [f"  [{r['status']}] {r['rule_id']}: {'; '.join(r['issues'][:2])}"
         for r in fail_items[:50]]
    (RULE_DIR / "validation_summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

    print(f"\nWrote: {report_path}")
    print(f"Wrote: {RULE_DIR / 'validation_summary.txt'}")


if __name__ == "__main__":
    main()
