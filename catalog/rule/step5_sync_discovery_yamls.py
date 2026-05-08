#!/usr/bin/env python3
"""
step5_sync_discovery_yamls.py
=============================
For every config rule whose for_each exists in the step6 data catalog but
is NOT yet in the deployed rule_check discovery YAML:
  → Copy the full discovery entry (calls + emit) from step6 into the
    deployed {csp}_rule_check/{svc}/{svc}.discovery.yaml

Also reports:
  - Rules whose for_each is ALREADY deployed (no action needed)
  - Rules whose for_each is NOWHERE (true stubs — need manual SDK work)

Outputs per service:
  catalog/rule/{csp}_rule_check/{svc}/{svc}.discovery.yaml  (patched/created)
  catalog/rule/sync_discovery_report.json

Usage:
    python3 catalog/rule/step5_sync_discovery_yamls.py             # dry-run
    python3 catalog/rule/step5_sync_discovery_yamls.py --apply     # write files
    python3 catalog/rule/step5_sync_discovery_yamls.py --apply --csp ibm
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
DGD      = ROOT / "catalog" / "discovery_generator_data"

APPLY      = "--apply" in sys.argv
FILTER_CSP = None
for i, a in enumerate(sys.argv):
    if a == "--csp" and i + 1 < len(sys.argv):
        FILTER_CSP = sys.argv[i + 1].lower()

if not APPLY:
    print("*** DRY-RUN — pass --apply to write files ***\n")

# ─────────────────────────────────────────────────────────────────────────────
# 1. Load full step6 catalog: discovery_id → full entry dict
# ─────────────────────────────────────────────────────────────────────────────
print("Loading step6 discovery catalog ...")
STEP6_ENTRIES: dict[str, dict] = {}   # discovery_id → entry dict
STEP6_META: dict[str, dict]    = {}   # discovery_id → {csp, svc, path}

for f in DGD.rglob("step6_*.yaml"):
    csp = f.parts[-3]
    svc = f.parts[-2]
    try:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    except Exception:
        continue
    for entry in (data.get("discovery") or []):
        if not isinstance(entry, dict):
            continue
        did = entry.get("discovery_id", "")
        if did:
            STEP6_ENTRIES[did] = entry
            STEP6_META[did]    = {"csp": csp, "svc": svc, "path": str(f)}

print(f"  {len(STEP6_ENTRIES):,} discovery_ids in step6 catalog")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Load deployed discovery IDs in rule_check dirs
# ─────────────────────────────────────────────────────────────────────────────
print("Loading deployed discovery IDs ...")
DEPLOYED: dict[str, Path] = {}   # discovery_id → yaml file path

for csp in ["alicloud", "aws", "azure", "gcp", "ibm", "k8s", "oci"]:
    chk_dir = RULE_DIR / f"{csp}_rule_check"
    if not chk_dir.exists():
        continue
    for f in chk_dir.rglob("*.yaml"):
        if "discovery" not in f.name:
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for entry in (data.get("discovery") or []):
            if isinstance(entry, dict) and "discovery_id" in entry:
                DEPLOYED[entry["discovery_id"]] = f

print(f"  {len(DEPLOYED):,} already deployed")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Load discovery resolution from step2
# ─────────────────────────────────────────────────────────────────────────────
res_path = RULE_DIR / "discovery_resolution.json"
RESOLUTION: dict = json.loads(res_path.read_text()) if res_path.exists() else {}

# ─────────────────────────────────────────────────────────────────────────────
# 4. Find what needs syncing
# ─────────────────────────────────────────────────────────────────────────────
# Group by (target_csp, target_svc_dir): for_each_id → [rule_ids]
# The target svc dir is where the rule_check checks.yaml lives
# We infer it from the rule_id:  {csp}.{raw_svc}.*.* → rule_check/{service}/

def norm_csp(c: str) -> str:
    return "oci" if c == "oracle" else c

def extract_service(rule_id: str) -> str:
    _OVER = {
        "actiontrail": "actiontrail", "ecs": "compute", "ram": "iam",
        "oos": "compute", "sas": "threat", "securitycenter": "threat",
        "resourcemanager": "iam", "slb": "network", "voicenavigator": "network",
        "chime": "network", "cloudtrail": "logging", "ec2": "compute",
        "ssm": "compute", "aad": "iam", "compute": "compute", "vm": "compute",
        "monitor": "logging", "communication": "network",
        "cloudaudit": "logging", "osconfig": "compute", "logging": "logging",
        "contactcenterinsights": "network",
        "activity_tracker": "logging", "activitytracker": "logging",
        "cloudant": "database", "codeengine": "compute", "functions": "compute",
        "schematics": "compute", "security_advisor": "threat",
        "securityadvisor": "threat", "vpc": "network", "is": "network",
        "watson": "network", "apiserver": "logging", "audit": "logging",
        "container": "compute", "falco": "threat", "node": "compute",
        "announcements": "network",
    }
    raw = rule_id.split(".")[1] if "." in rule_id else "unknown"
    return _OVER.get(raw, raw)

# Build sync plan: (csp, svc) → {for_each_id → [rule_ids]}
sync_plan: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(
    lambda: defaultdict(list)
)
already_ok:   list[str] = []
true_stubs:   list[str] = []
cannot_find:  list[str] = []

for rule_id, res in RESOLUTION.items():
    if res.get("status") != "resolved":
        true_stubs.append(rule_id)
        continue

    csp     = res["csp"]
    if FILTER_CSP and csp != FILTER_CSP:
        continue

    for_each = res["for_each"]
    service  = extract_service(rule_id)

    if for_each in DEPLOYED:
        already_ok.append(rule_id)
        continue

    if for_each in STEP6_ENTRIES:
        sync_plan[(csp, service)][for_each].append(rule_id)
    else:
        cannot_find.append(rule_id)

total_to_sync = sum(len(ids) for ids_map in sync_plan.values()
                    for ids in ids_map.values())

print(f"\nSync plan:")
print(f"  Already deployed (no action): {len(already_ok)}")
print(f"  Need to sync from step6     : {total_to_sync} rules "
      f"({sum(len(m) for m in sync_plan.values())} unique for_each IDs)")
print(f"  True stubs (no discovery)   : {len(true_stubs)}")
print(f"  Cannot find anywhere        : {len(cannot_find)}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. Build the emit template with REAL fields from step6
# ─────────────────────────────────────────────────────────────────────────────

def _clean_entry(entry: dict) -> dict:
    """
    Return a clean copy of a step6 entry suitable for the deployed discovery YAML.
    Removes stub flags, preserves calls + emit.
    """
    clean = {
        "discovery_id": entry["discovery_id"],
    }
    # Preserve calls block
    if "calls" in entry:
        clean["calls"] = entry["calls"]

    # Preserve emit block — ensure it has real item fields
    emit = entry.get("emit", {})
    if isinstance(emit, dict):
        # If emit.item is a dict of field → template, keep it
        if isinstance(emit.get("item"), dict) and emit["item"]:
            clean["emit"] = emit
        else:
            # Emit exists but item is empty/missing — add standard fields
            clean["emit"] = {
                "as":        emit.get("as", "item"),
                "items_for": emit.get("items_for", "{{ response }}"),
                "item": {
                    "id":              "{{ item.Id }}",
                    "name":            "{{ item.Name }}",
                    "resource_type":   "{{ resource_type }}",
                    "region":          "{{ region }}",
                    "status":          "{{ item.Status }}",
                    "enabled":         "{{ item.Enabled }}",
                    "logging_enabled": "{{ item.LoggingEnabled }}",
                    "encrypted":       "{{ item.Encrypted }}",
                    "kms_key_id":      "{{ item.KMSKeyId }}",
                    "tags":            "{{ item.Tags }}",
                },
            }
    else:
        clean["emit"] = {
            "as":        "item",
            "items_for": "{{ response }}",
            "item": {
                "id":              "{{ item.Id }}",
                "name":            "{{ item.Name }}",
                "resource_type":   "{{ resource_type }}",
                "region":          "{{ region }}",
                "status":          "{{ item.Status }}",
                "enabled":         "{{ item.Enabled }}",
                "logging_enabled": "{{ item.LoggingEnabled }}",
                "encrypted":       "{{ item.Encrypted }}",
                "kms_key_id":      "{{ item.KMSKeyId }}",
                "tags":            "{{ item.Tags }}",
            },
        }

    # Remove internal step2 stub flags if present
    for key in ("_stub", "_note", "_rules", "_client"):
        clean.pop(key, None)

    return clean


# ─────────────────────────────────────────────────────────────────────────────
# 6. Write / patch deployed discovery YAMLs
# ─────────────────────────────────────────────────────────────────────────────

written_files:  list[str] = []
written_entries = 0

for (csp, svc), for_each_map in sorted(sync_plan.items()):
    svc_dir   = RULE_DIR / f"{csp}_rule_check" / svc
    disc_file = svc_dir / f"{svc}.discovery.yaml"

    # Load existing deployed discovery YAML for this service
    existing_ids: set[str] = set()
    existing_entries: list[dict] = []
    header: dict = {}

    if disc_file.exists():
        try:
            data = yaml.safe_load(disc_file.read_text(encoding="utf-8")) or {}
            header   = {k: v for k, v in data.items() if k != "discovery"}
            existing_entries = [e for e in (data.get("discovery") or [])
                                if isinstance(e, dict)]
            existing_ids = {e.get("discovery_id", "") for e in existing_entries}
        except Exception:
            pass
    else:
        header = {
            "version":  "1.0",
            "provider": csp,
            "service":  svc,
        }

    # Add new entries
    new_entries: list[dict] = []
    for for_each_id, rule_ids in sorted(for_each_map.items()):
        if for_each_id in existing_ids:
            continue
        step6_entry = STEP6_ENTRIES[for_each_id]
        clean       = _clean_entry(step6_entry)
        clean["_used_by_rules"] = rule_ids  # informational comment
        new_entries.append(clean)
        existing_ids.add(for_each_id)

    if not new_entries:
        continue

    all_entries = existing_entries + new_entries
    out = {**header, "discovery": all_entries}

    if APPLY:
        svc_dir.mkdir(parents=True, exist_ok=True)
        disc_file.write_text(
            yaml.dump(out, allow_unicode=True, sort_keys=False,
                      default_flow_style=False),
            encoding="utf-8",
        )
        written_files.append(str(disc_file.relative_to(ROOT)))

    written_entries += len(new_entries)
    status = "WRITE" if APPLY else "DRY"
    print(f"  [{status}] {csp}/{svc}: +{len(new_entries)} discovery entries"
          f"  (covers {sum(len(r) for r in for_each_map.values())} rules)")

# ─────────────────────────────────────────────────────────────────────────────
# 7. Report
# ─────────────────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"SYNC COMPLETE")
print(f"  Discovery entries added : {written_entries}")
print(f"  Files written           : {len(written_files)}")
print(f"  Already deployed        : {len(already_ok)}")
print(f"  True stubs (no data)    : {len(true_stubs)}")
print(f"  Unresolvable            : {len(cannot_find)}")

if cannot_find:
    print(f"\nCannot find anywhere ({len(cannot_find)}):")
    for r in cannot_find[:15]:
        print(f"  {r}  → {RESOLUTION.get(r,{}).get('for_each','?')}")

# Write JSON report
report = {
    "written_entries": written_entries,
    "written_files":   written_files,
    "already_deployed": len(already_ok),
    "true_stubs": true_stubs,
    "cannot_find": cannot_find,
    "sync_plan": {
        f"{csp}|{svc}": list(for_each_map.keys())
        for (csp, svc), for_each_map in sync_plan.items()
    },
}
(RULE_DIR / "sync_discovery_report.json").write_text(
    json.dumps(report, indent=2), encoding="utf-8"
)
print(f"\nWrote: catalog/rule/sync_discovery_report.json")
if not APPLY:
    print("\n*** Pass --apply to write discovery YAML files ***")
